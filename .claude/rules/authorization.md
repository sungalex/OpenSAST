---
paths:
  - "opensast/api/**/*.py"
  - "opensast/services/**/*.py"
  - "opensast/db/**/*.py"
  - "opensast/config.py"
  - "alembic/**/*.py"
---

# 인가 경계 · 설정 · 스키마 (ADR-0005 / 0006)

지금 읽고 있는 파일은 **테넌트 데이터의 경계**에 있다.

## ActorContext 는 선택이 아니다

서비스는 `ActorContext` 를 **요구**한다. `None` 을 넘기면 `TypeError` 다.
"일단 동작하게" 하려고 우회하지 않는다.

| 호출자 | 액터 |
|---|---|
| HTTP 라우트 | `Depends(get_actor)` / `Depends(require_actor(*roles))` |
| 미인증 경로 (로그인 시도 등) | `ActorContext.anonymous()` |
| CLI · Celery · 부트스트랩 | `ActorContext.system(reason=...)` — `reason` 을 비우지 않는다 |

`BaseService._org_filter()` 는 **deny-by-default** 다. 액터의
`organization_id` 와 일치하는 행만 통과한다. 전체 접근은 `ActorContext.system()`
으로만 얻는다.

## 라우트에서 하지 않을 일

- **`select(models.X)` 를 라우트 안에 쓰지 않는다.** 테넌트 데이터를 만지는
  모든 경로는 서비스를 경유한다. `audit.py` 와 `organizations.py` 가 이 규칙을
  어겨 ADR-0005 이후에도 조직 간 누출이 남아 있었다.
- 응답 dict 를 라우트 안에서 조립하지 않는다 — `api/schemas.py` 에 정의한다.
- 라우트는 얇은 어댑터다. 계약은 "서비스에 액터를 주입한다" 뿐이다.

## 설정 (ADR-0006)

`opensast/config.py` 가 **유일한** 진실의 원천이다. 한계값·타임아웃·경로를
서비스나 미들웨어에 하드코딩하지 않는다. 문서와 코드가 어긋나면 코드가 정본이다.

프로파일: `local`(완화·docs 노출) / `docker` / `cloud`(docs 비활성·JSON 로그·
약한 시크릿이나 빈 CORS 로는 **기동 거부**). `OPENSAST_PROFILE` 미지정 시 `local`.

## 스키마

- Alembic 리비전 **`0001` 은 동결된 명시적 DDL** 이다. 여기에
  `Base.metadata.create_all()` 을 다시 넣으면 체인 전체가 깨진다.
- `db/migrate.py::auto_migrate()` 는 개발 전용 폴백이며 cloud 프로파일에서 비활성.
- 스키마 변경은 **새 리비전**으로만.

## 공통

- 타임스탬프는 전부 timezone-aware UTC.
- 경로 봉쇄는 `Path.is_relative_to()`. 문자열 prefix 비교 금지.
- 실패는 단위별로 격리하고 **로깅한다**. `except: pass` 금지.

## 변경 후 필수 검증

```bash
.venv/bin/python -m pytest tests/test_authorization_boundary.py tests/test_security_regressions.py -q --tb=short
```

새 엔드포인트를 만들었다면 `tests/test_authorization_boundary.py` 에
**조직 A 가 조직 B 의 행을 볼 수 없다**는 케이스를 추가한다.
