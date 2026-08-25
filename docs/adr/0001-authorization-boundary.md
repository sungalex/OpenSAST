# ADR-0001: 인가 강제 지점을 서비스 계층에서 라우트 계약으로 끌어올린다

**Status:** Accepted
**Date:** 2026-08-25
**Deciders:** 백엔드 오너

## Context

인가 로직 자체는 `BaseService` 에 잘 설계되어 있었다. 서비스가 `ActorContext` 를
받아 조직 스코핑(`_org_filter`)과 역할 검증(`require_role`)을 수행한다.

문제는 그 로직이 **작동하기 위한 전제**가 선택 사항이었다는 점이다.

```python
# 예전 시그니처
def __init__(self, session, actor: ActorContext | None = None):
    self.actor = actor or ActorContext(user=None)

def _org_filter(self, model_class):
    org_id = self.actor.organization_id if self.actor else None
    if org_id is None:
        return True          # ← 필터 없음 = 전체 통과
    return model_class.organization_id == org_id
```

즉 **라우트가 actor 를 빠뜨리면 조직 격리가 통째로 사라지고, 기본값이 "전체 허용"
이었다.** 실제로 다음이 일어났다.

- 조회 라우트 8곳이 `ScanService(db)` / `FindingService(db)` 형태로 actor 없이
  서비스를 생성 — 타 조직의 스캔·Finding·소스 파일이 그대로 열람 가능
- 대시보드 5개 엔드포인트는 아예 `_: User = Depends(...)` 로 사용자를 버리고
  ORM 을 직접 호출 — 전역 집계 반환
- `deps.py` 에 준비된 `require_org_access()` 는 라우트에서 **참조 0건**
- API 전체에서 `require_role` 을 쓰는 라우트가 `auth.py` 하나뿐이어서,
  ARCHITECTURE §4.3 RBAC 표(`viewer` 는 스캔 실행 ✗)가 사실상 미강제
- `POST /api/scans` 는 `source_path` 를 검증 없이 받아, 어떤 인증 사용자든
  `/etc` 를 스캔한 뒤 `GET /api/scans/{id}/source` 로 읽어낼 수 있었다
- `GET /api/scans/{id}/events`(SSE)에는 인증 의존성이 아예 없었다

8개 라우트를 개별로 고치는 것은 재발을 막지 못한다. 다음에 추가되는 라우트도
같은 방식으로 틀릴 수 있고, 틀렸을 때 **아무 신호가 없다**.

## Decision

**인가에 필요한 정보를 옵션으로 두지 않는다.** 세 가지를 함께 바꾼다.

### 1. `ActorContext` 를 필수 인자로

```python
class BaseService:
    def __init__(self, session: Session, actor: ActorContext) -> None:
        if not isinstance(actor, ActorContext):
            raise TypeError(...)
```

라우트가 빠뜨리면 요청 처리 중 `TypeError` 로 즉시 드러난다. 조용히 권한이
넓어지는 대신 시끄럽게 실패한다.

### 2. 미인증·시스템 컨텍스트를 명시적 팩토리로만

```python
ActorContext.anonymous(ip=..., user_agent=...)   # 로그인 시도 등
ActorContext.system(reason="cli")                # CLI · Celery · 부트스트랩
```

"actor 를 안 넘김" 과 "의도적으로 권한 없는 컨텍스트" 를 구분한다. 전자는 실수,
후자는 선언이다.

### 3. `_org_filter` 의 기본값을 차단으로 반전

```python
def _org_filter(self, model_class):
    if self.actor.is_system:
        return true()
    return model_class.organization_id == self.actor.organization_id
```

actor 의 조직과 일치하는 레코드만 통과한다. 조직 미지정 사용자는 조직 미지정
레코드만 본다 — SQLAlchemy 가 `IS NULL` 로 컴파일하므로 단일 테넌시 배포도
그대로 동작한다. 전체 조회는 `system` 컨텍스트에서만 가능하다.

### 함께 적용한 것

- 라우트는 `get_actor` / `require_actor(*roles)` 의존성으로만 `ActorContext` 를
  만든다. `deps.py` 의 `WRITE_ROLES` 상수가 RBAC 표의 코드 표현이다.
- 대시보드 집계를 `DashboardService` 로 옮겨 다른 조회와 같은 필터를 지난다.
- `ServiceError` → HTTP 변환을 앱 전역 예외 핸들러 한 곳으로 모은다.
  라우트마다 try/except 를 반복하면 한 곳만 빠뜨려도 500 이 새어 나간다
  (실제로 조직 스코핑 404 가 500 으로 노출됐다).
- 경로 스캔은 `settings.scan_allowed_source_roots` 안에서만 허용하고, 워커도
  큐 메시지를 그대로 믿지 않고 같은 검증을 다시 한다.
- SSE 는 일반 라우트와 동일하게 인증·스코핑하며, `EventSource` 가 헤더를 보낼 수
  없으므로 Authorization 헤더가 없을 때만 `?access_token=` 을 대안으로 받는다.

## Options Considered

| 안 | 복잡도 | 재발 방지 | 평가 |
|---|---|---|---|
| A. 8개 라우트 개별 수정 | 낮음 | 없음 | 즉시 완화되나 다음 라우트에서 재발. 신호가 없다 |
| **B. actor 필수화 + 기본값 반전 (채택)** | 중간 | 타입/런타임 수준 | 누락이 즉시 실패로 드러난다 |
| C. 미들웨어에서 조직 스코핑 강제 | 높음 | 부분적 | SQLAlchemy 이벤트 훅으로 쿼리를 가로채야 하고, 그 자체가 큰 부채 |

C 는 "개발자가 잊어도 안전" 이라는 점에서 매력적이지만, ORM 쿼리 가로채기는
디버깅이 어렵고 집계·조인 쿼리에서 예외 케이스가 많다. B 는 개발자가 잊으면
**실패**하므로, 잊어도 통과하던 예전보다 확실히 낫다.

## Consequences

**쉬워지는 것**

- 신규 라우트가 인가를 빠뜨리면 즉시 실패한다. 조용한 권한 확대가 불가능해진다.
- 이미 완료돼 있던 멀티테넌시 스키마(alembic 0003)가 처음으로 실제 효력을 갖는다.
- 조직 격리를 한 곳(`_org_filter`, `_assert_org`)에서만 정의한다.

**어려워지는 것**

- 기존 라우트·테스트를 한 번에 갱신해야 했다.
- 배치·CLI 경로에서 `ActorContext.system()` 을 명시해야 한다. 이는 의도적인
  마찰이다 — 권한 우회는 눈에 보여야 한다.
- `viewer` 역할 사용자는 이제 스캔을 큐잉할 수 없다. RBAC 표대로지만
  **동작 변경**이므로 릴리스 노트에 명시해야 한다.

**다시 볼 것**

- 역할 검사가 라우트 데코레이터(`require_actor`)와 서비스 내부
  (`actor.require_role`) 양쪽에 남아 있다. 지금은 2중 방어선으로 의도한 것이지만,
  어느 쪽을 정본으로 할지 v0.6 이전에 결정한다.
- JWT 에 `org_id` 클레임이 있으나 `get_actor` 는 DB 의 사용자 레코드에서 읽는다.
  조직 이동 후 옛 토큰이 옛 권한을 유지하는 것을 막기 위해서인데, 요청마다 DB
  조회 비용이 든다. Redis 캐시 도입 시 재검토.

## Action Items

1. [x] `POST /api/scans` 에 쓰기 역할 요구 + `source_path` 허용 루트 화이트리스트
2. [x] SSE 에 인증 의존성 추가 및 요청 세션과 스트림 세션 분리
3. [x] `ActorContext.anonymous()` / `.system()` 도입, `BaseService` 시그니처 변경
4. [x] `_org_filter` 기본값 반전, 라우트 전수 갱신, `DashboardService` 신설
5. [x] `ServiceError` 전역 예외 핸들러
6. [x] 회귀 테스트 — 조직 A 사용자가 조직 B 의 scan/finding/source/report/dashboard
       접근 시 404 (`tests/test_authorization_boundary.py`)
