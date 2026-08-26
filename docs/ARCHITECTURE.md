# OpenSAST 아키텍처 (as-built)

> **성격**: As-built — **지금 코드가 하는 일**만 기술한다.
> 계획·희망사항·"향후" 는 여기 쓰지 않는다. 그런 내용은
> [`ROADMAP.md`](ROADMAP.md), 결정의 근거는 [`adr/`](adr/README.md) 에 있다.
> 이 원칙은 [ADR-0007](adr/0007-documentation-architecture.md) 에서 정했다.
>
> **동작을 바꾸는 PR 은 이 문서를 함께 고친다.**

## 설계 목표

1. **플러그인 기반 확장** — 엔진/레퍼런스/리포트/LLM 을 코어 수정 없이 추가
2. **3-tier 배포 프로파일** — 로컬 / Docker / Cloud 를 단일 코드베이스로 지원
3. **커스터마이징 격리** — 패키지 업그레이드가 사용자 커스텀을 깨지 않음
4. **Secure by default** — 인증·권한·네트워크·저장소 전 계층 기본값이 안전

---

## 1. 계층 구조

```
┌─────────────────────────────────────────────────────────────────┐
│                     ① Web Tier (Edge)                           │
│   nginx (TLS terminate · static serve · /api proxy)             │
│   └── React SPA (Vite build → static bundle)                    │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼  HTTPS / Authorization 헤더
┌─────────────────────────────────────────────────────────────────┐
│                     ② WAS Tier (App Server)                     │
│                                                                 │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  FastAPI Routes  (thin HTTP adapters)                  │    │
│   │     │  get_actor / require_actor 로 ActorContext 주입   │    │
│   │     ▼                                                  │    │
│   │  Service Layer  (business logic, transactions,         │    │
│   │                  audit emission, RBAC + 조직 스코핑)    │    │
│   │     │                                                  │    │
│   │     ▼                                                  │    │
│   │  Repository Layer  (SQLAlchemy query composition)      │    │
│   │     │                                                  │    │
│   │     ▼                                                  │    │
│   │  Plugin Registry  (engines, LLMs, reports, refs)       │    │
│   │     │                                                  │    │
│   │     ▼                                                  │    │
│   │  Extension Hooks  (pre/post scan, on_status_change)    │    │
│   └────────────────────────────────────────────────────────┘    │
│                                                                 │
│   Celery Workers (scan execution, clone_and_scan, triage)       │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼  SQL / Redis / FS
┌─────────────────────────────────────────────────────────────────┐
│                     ③ Data Tier                                 │
│   Postgres           Redis            Filesystem         Ollama │
│   (primary RW)       (queue+cache)    (.opensast-work)   (local)│
└─────────────────────────────────────────────────────────────────┘
```

각 티어는 독립적으로 수평 확장되며, 모든 요청은 ① → ② → ③ 단방향으로 흐른다.

---

## 2. 애플리케이션 아키텍처

### 2.1 라우트 → 서비스 → 레포 3계층

라우트는 얇은 어댑터다. **인가에 필요한 정보(`ActorContext`)를 서비스에 주입하는
것이 라우트의 계약**이며, 이를 빠뜨리면 서비스 생성자가 `TypeError` 를 던진다
([ADR-0005](adr/0005-authorization-boundary.md)).

```python
# 라우트 — Pydantic 검증 + ActorContext 주입 + 서비스 호출
@router.post("", status_code=202)
def queue_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(*WRITE_ROLES)),
) -> ScanOut:
    scan = ScanService(db, actor).queue_from_path(...)
    return ScanOut.model_validate(scan)

# 서비스 — 트랜잭션 경계, 비즈니스 규칙, 감사 로그, 2차 권한 방어선
class ScanService(BaseService):
    def queue_from_path(self, *, project_id, source_path, ...):
        self.actor.require_role("admin", "analyst")
        project = ProjectService(self.session, self.actor).get(project_id)
        resolved = self._validate_source_path(source_path)
        ...
```

`ServiceError` → HTTP 변환은 앱 전역 예외 핸들러 한 곳에서만 한다. 라우트마다
try/except 를 반복하면 한 곳만 빠뜨려도 500 이 새어 나간다.

ASGI 애플리케이션(`opensast.api.app:app`)은 **지연 생성**된다(PEP 562 `__getattr__`).
모듈 import 는 부작용이 없고, 속성에 처음 접근할 때 한 번만 만들어진다. 예전처럼
최상단에서 `create_app()` 을 실행하면 하위 모듈 하나를 import 하는 것만으로
설정 검증·DB 엔진·플러그인 탐색이 전부 돌아, cloud 프로파일에서는 토큰 헬퍼조차
import 할 수 없었다.

**효과**: 라우트 단위 테스트는 서비스 모킹만으로 가능하고, 동일한 비즈니스
로직을 CLI·Celery·Webhook 어디서든 재사용하며, 감사 로그가 서비스 계층에
집중되어 누락되지 않는다.

### 2.2 인가 모델

`ActorContext` 는 세 가지 방법으로만 만들어진다.

| 생성 방법 | 용도 | 조직 스코핑 |
|---|---|---|
| `Depends(get_actor)` / `require_actor(*roles)` | HTTP 요청 | actor 의 조직으로 제한 |
| `ActorContext.anonymous(...)` | 로그인 시도 등 미인증 경로 | 아무것도 통과 못 함 |
| `ActorContext.system(reason=...)` | CLI · Celery 워커 · 부트스트랩 | 우회 |

`BaseService._org_filter()` 의 기본값은 **차단**이다. actor 의
`organization_id` 와 일치하는 레코드만 통과하며, 조직 미지정 사용자는 조직
미지정 레코드만 본다(SQLAlchemy 가 `IS NULL` 로 컴파일하므로 단일 테넌시
배포에서도 정상 동작). 전체 조회는 `system` 컨텍스트에서만 가능하다.

`organization_id` 는 JWT 클레임이 아니라 **DB 의 사용자 레코드**에서 읽는다.
조직 이동 후에도 기존 토큰이 옛 권한을 유지하는 것을 막기 위해서다.

### 2.3 플러그인 레지스트리

모든 확장 포인트는 동일한 `Registry[T]` 패턴으로 관리된다.

```python
# 내장 등록 (priority=50)
engine_registry.register("opengrep", OpengrepEngine, source="builtin", priority=50)

# 외부 패키지가 entry_points 로 등록
# pyproject.toml:
#   [project.entry-points."opensast.engines"]
#   xyz = "my_plugin:XyzEngine"

engine_registry.get("opengrep")   # 조회
engine_registry.all()             # 전체
```

| 그룹 | entry_point 그룹 | 인터페이스 | 배선 위치 |
|------|------------------|-----------|-----------|
| 분석 엔진 | `opensast.engines` | `Engine` | `engines/registry.py` |
| LLM 프로바이더 | `opensast.llm` | `LLMClient` | `llm/__init__.py` |
| 리포트 포맷 | `opensast.reports` | `(scan, findings) -> bytes` | `reports/__init__.py` |
| 레퍼런스 표준 | `opensast.references` | `ReferenceProvider` | `mois/references.py` |
| 수명주기 훅 | `opensast.hooks` | `ScanHook` | `hooks.py` |

플러그인 로드 실패는 로그만 남기고 계속 진행한다 — 하나가 깨져도 시스템이 멈추지
않는다. `OPENSAST_PLUGINS_DISABLED="name1,name2"` 로 선택 차단할 수 있다.

`build_engine()` 은 등록되지 않은 이름에 대해 `UnknownEngine` 을 던지고,
파이프라인은 이를 잡아 경고 후 건너뛴다.

### 2.4 확장 훅

```python
class ScanHook(Protocol):
    def pre_scan(self, scan_id: str, target: ScanTarget) -> None: ...
    def post_scan(self, scan_id: str, result: ScanResult) -> None: ...
    def pre_persist(self, scan_id: str, result: ScanResult) -> None: ...
    def post_persist(self, scan_id: str, scan: models.Scan) -> None: ...
    def on_status_change(self, finding, old_status: str, new_status: str) -> None: ...
```

정의되지 않은 콜백은 무시되며(duck typing), 훅 내 예외는 격리되어 호출자에게
전파되지 않는다. 커스텀 감사·알림·Jira/Slack 연동을 코어 수정 없이 추가할 수 있다.

### 2.5 설정 프로파일

`OPENSAST_PROFILE ∈ {local, docker, cloud}` 이 기본값 번들을 전환한다.
**정본은 `opensast/config.py` 의 `_PROFILE_DEFAULTS` 다** — 아래 표는 그것을
서술할 뿐이며, 불일치가 생기면 코드가 옳다
([ADR-0006](adr/0006-configuration-single-source.md)).

| 항목 | local | docker | cloud |
|------|-------|--------|-------|
| `cors_origins` | `["*"]` | `localhost:8080` | 빈 값 (env 로 필수 주입) |
| `enable_docs` | true | true | false |
| `rate_limit_per_minute` | 0 (off) | 100 | 60 |
| `db_pool_size` | 5 | 10 | 20 |
| `log_level` / `log_format` | DEBUG / console | INFO / console | INFO / json |
| `enforce_strong_secret` | false | false | **true** |
| `fail_fast_on_config_warning` | false | false | **true** |
| `auto_migrate_on_startup` | true | true | **false** |

cloud 프로파일에서는 설정 경고가 **기동 실패**다. 약한 시크릿, 빈/와일드카드
CORS, 기본 부트스트랩 비밀번호로는 뜨지 않는다.

모든 값은 `OPENSAST_*` 환경변수로 재정의된다. 우선순위(낮음 → 높음):
프로파일 기본값 → 오버레이 YAML(`OPENSAST_OVERLAY_CONFIG`) → 환경변수 / `.env`.

---

## 3. 데이터 아키텍처

### 3.1 스키마 관리

- **Alembic 이 정식 마이그레이션 도구다.** `alembic/versions/` 에 리비전이
  버전 관리된다. 초기 리비전(0001)은 **명시적 DDL 로 동결**되어 있다 —
  `create_all` 을 쓰면 "현재 모델" 이라는 움직이는 표적을 따라가면서 이후
  리비전과 충돌하고, 모든 변경이 초기 리비전에 흡수되어 히스토리가 무의미해진다.
- 모델 변경 → `alembic revision --autogenerate -m "..."` → 리뷰 → 커밋
- `db/migrate.py::auto_migrate()` 는 **개발 전용 fallback** 이며 컬럼 추가만
  지원한다. `auto_migrate_on_startup` 이 True 일 때만 호출되고, cloud
  프로파일에서는 꺼져 있다. 프로덕션은 `alembic upgrade head` 를 배포
  파이프라인에서 실행한다.
- `alembic/env.py` 는 호출자가 명시한 URL 을 우선하고, 없을 때만 설정에서 읽는다.

### 3.2 Repository 패턴

| 집합(Aggregate) | 접근 경로 |
|----------------|-----------|
| User | `repo.ensure_bootstrap_admin` 등 |
| Project · Scan · Finding · Triage | `ProjectService` / `ScanService` / `FindingService` |
| RuleSet · Suppression · GatePolicy | `RuleSetService` / `SuppressionService` / `GateService` |
| 대시보드 집계 | `DashboardService` |
| AuditLog | `repo.record_audit` (서비스의 `_audit` 헬퍼 경유) |

각 서비스는 단일 SQLAlchemy Session 을 주입받으며, 커밋은 서비스 계층에서 한다.

도메인 모델(`opensast/models.py`) ↔ ORM(`opensast/db/models.py`) 변환은
`opensast/db/mapping.py` 한 곳에 모여 있다. 예전에는 세 곳에 흩어져 있어
역방향 변환에서 `raw` 필드가 유실됐다.

### 3.3 3-Tier 데이터 배포

| 배포 모드 | Postgres | Redis | 파일 스토리지 | Ollama |
|----------|----------|-------|--------------|--------|
| **Local** | SQLite 파일 또는 로컬 Postgres | 선택 | `<cwd>/.opensast-work` | 선택 |
| **Docker compose** | `postgres:16-alpine` + named volume | `redis:7-alpine` | 호스트 `./.opensast-work` bind-mount | `ollama:latest` |
| **Cloud** | 관리형 Postgres | 관리형 Redis | PVC · NFS · CSI 등 공유 볼륨 | Anthropic API 또는 GPU 노드 |

연결 문자열만 환경변수로 주입하면 동일 이미지가 세 모드 모두에서 동작한다.

> **주의**: `work_dir` 기본값은 프로세스 CWD 기준이다. API 와 워커가 서로 다른
> CWD 로 뜨면 같은 상대 경로가 다른 절대 경로로 해석되므로, 다중 프로세스
> 배포에서는 `OPENSAST_WORK_DIR` 을 절대 경로로 반드시 명시한다.

### 3.4 캐싱

| 데이터 | 저장소 | TTL |
|--------|--------|-----|
| MOIS 49 catalog | 프로세스 메모리 (import 시 1회) | 프로세스 수명 |
| 레퍼런스 매핑 오버레이 | 프로세스 메모리 | 프로세스 수명 |
| LLM triage 결과 | Redis (`triage:<sha256>`) | `triage_cache_ttl_seconds` (기본 24h) |
| JWT deny-list / refresh 소비 표시 | Redis | 토큰 exp 까지 |

Redis 클라이언트는 URL 당 하나(커넥션 풀)를 재사용한다. 캐시 접근이 실패하면
**최초 1회 WARNING** 을 남기고 그 실행 동안 캐시를 비활성화한다 — 조용한 성능
저하를 만들지 않는다 ([ADR-0008](adr/0008-triage-concurrency.md)).

### 3.5 파일·소스코드 저장

- 업로드 ZIP 과 git clone 체크아웃은 `OPENSAST_WORK_DIR` 하위에 저장된다.
- ZIP 해제는 경로 탈출(`Path.is_relative_to` 로 검사)과 압축 확대율(zip bomb)을
  모두 검사한다.
- clone 체크아웃은 성공·실패·예외 어느 경로로 빠져나가든 `finally` 에서 정리된다.
- 완료된 스캔 결과는 DB 에만 보존되며 원본 소스는 클린업된다.

---

## 4. 보안 아키텍처

### 4.1 인증

- JWT HS256. `sub` / `role` / `exp` / `iat` / `jti` / `type` / `iss` / `aud` /
  `org_id` 클레임 포함. 수명은 `access_token_expire_minutes`(기본 24h).
- **Refresh token** — `HttpOnly` 쿠키, 회전(rotation), Redis 기반 소비 표시
- **토큰 블랙리스트** — Redis 에 `jti` 저장, 로그아웃 즉시 무효화
- 비밀번호 해싱: **bcrypt 직접** (passlib 미사용, bcrypt>=4.1 호환).
  UTF-8 NFC 정규화 후 72 바이트 상한 적용.
- 이메일: 느슨한 정규식 + 소문자 정규화 (`.local` 등 내부망 도메인 허용)

### 4.2 계정 보안

| 방어 | 구현 |
|------|------|
| 비밀번호 정책 | 최소 12자, 대·소·숫자·특수 중 3종 이상, 흔한 비밀번호 블랙리스트 |
| 계정 잠금 | 연속 실패 5회 시 15분 잠금 (`users.failed_attempts`, `users.locked_until`) |
| 실패 감사 | 모든 실패 시도가 `audit_logs` 에 기록 (IP 포함) |
| 부트스트랩 경고 | 기본 비밀번호 사용 시 로그 WARNING, **cloud 프로파일에서는 기동 거부** |

### 4.3 권한 (RBAC)

세 역할. **강제 지점은 `api/deps.py` 의 `require_actor(*roles)` 와 서비스의
`actor.require_role(...)` 두 곳이다** — 아래 표는 그 코드를 서술한다.

| 역할 | 스캔 실행 | 이슈 조회 | 이슈 상태 변경 | 제외 승인 | 체커 그룹 관리 | 감사 로그 |
|------|:-:|:-:|:-:|:-:|:-:|:-:|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `analyst` | ✓ | ✓ | ✓ (제외 승인 제외) | ✗ | ✗ | ✗ |
| `viewer` | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |

`exclusion_requested → excluded` 전이는 `admin` 만 가능하다
(`_ADMIN_TRANSITIONS`). 제외 규칙(suppression) 생성·삭제와 체커 그룹 관리도
`admin` 전용이다.

### 4.4 네트워크 / HTTP 보안

| 대책 | 구현 |
|------|------|
| CORS allowlist | 프로파일별 기본값, `OPENSAST_CORS_ORIGINS` 로 재정의. cloud 는 와일드카드 거부 |
| 보안 헤더 | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| CSRF | double-submit 쿠키 미들웨어 |
| Rate limiting | `slowapi` — 분당 60~100 (프로파일별). **현재 in-memory 이므로 다중 인스턴스에서는 우회 가능** |
| Request size | 업로드 500 MiB, 그 외 라우트 2 MiB (미들웨어) |
| TLS | production nginx 에서 HTTPS 종료 |
| docs 노출 | cloud 프로파일에서 `/openapi.json`, `/docs`, `/redoc` 비활성 |
| Swagger 자산 | CDN 대신 `/static` 로컬 서빙 (폐쇄망 지원) |

### 4.5 입력 검증 & OWASP 자체 방어

- **SQL 삽입**: SQLAlchemy ORM 만 사용, 원시 쿼리 금지
- **Path Traversal**: `Path.is_relative_to()` 로 봉쇄. ZIP 해제, 소스 뷰어,
  LLM triage 컨텍스트 수집 세 곳 모두 적용. (문자열 `startswith` 는 형제
  디렉터리를 통과시키므로 쓰지 않는다)
- **임의 경로 스캔 차단**: `POST /api/scans` 의 `source_path` 는
  `scan_allowed_source_roots`(기본 `work_dir`) 안에서만 허용된다. 워커도 큐
  메시지를 그대로 믿지 않고 같은 검증을 반복한다.
- **SSRF**: Git URL 스킴 화이트리스트(`http/https/ssh/git@`). `git clone` 인자는
  `--` 로 분리해 옵션 주입을 막는다. **호스트 단위 allowlist 는 아직 없다.**
- **zip bomb**: 압축 확대율 100배 초과 또는 해제 후 4 GiB 초과 시 거부
- **XXE**: YAML/XML 파싱 시 `safe_load`, lxml 비사용
- **Deserialization**: pickle 사용 금지, JSON 만
- **오류 메시지 노출**: 내부 예외는 로그로만, 사용자에게는 일반화된 메시지
- **Self-SAST**: CI 파이프라인에서 opensast 가 자기 자신을 스캔해 회귀 차단

### 4.6 감사 & 모니터링

- `audit_logs` 테이블에 로그인/실패/이슈 상태 변경/제외 생성·삭제/게이트 판정/
  경로 거부 등을 기록. IP·user_id·timestamp·detail JSON 포함.
- 타임스탬프는 전 계층에서 타임존 인식 UTC 를 쓴다.
- 로그 포맷: 로컬 `rich` 콘솔, cloud 프로파일 JSON (Datadog/Stackdriver 호환)

---

## 5. 커스터마이징 격리

포크 없이 커스터마이징할 수 있는 6가지 확장 지점.

### 5.1 커스텀 룰 디렉터리

```bash
export OPENSAST_CUSTOM_RULES_DIR=/etc/opensast/my-rules
```

Opengrep 엔진이 내장 `rules/opengrep/` 과 이 디렉터리를 **동시에** `--config` 로
전달한다. 패키지 업그레이드가 내장 룰만 덮어쓴다.

### 5.2 커스텀 리소스 오버라이드

```bash
# 개별 파일 지정
export OPENSAST_MOIS_CATALOG_PATH=/etc/opensast/mois_override.yaml
export OPENSAST_REFERENCE_STANDARDS_PATH=/etc/opensast/refs_override.yaml

# 또는 디렉터리 하나로 (mois_catalog.yaml / reference_standards.yaml 자동 탐지)
export OPENSAST_CUSTOM_RESOURCES_DIR=/etc/opensast/resources
```

내장 YAML 위에 사용자 YAML 이 **merge** 된다. 행안부 개정판이 나오면 Python
수정 없이 YAML 하나만 배포하면 된다. 병합 결과는 ID 순으로 정렬되어 재현성이
보장된다.

### 5.3 플러그인 패키지

```
my-opensast-plugin/
├── pyproject.toml
│   └── [project.entry-points."opensast.engines"]
│       mysonar = "my_plugin:MySonarEngine"
└── my_plugin/__init__.py
```

`pip install my-opensast-plugin` 만으로 자동 발견된다.

### 5.4 훅 구독

```python
from opensast.hooks import ScanHook, hook_registry

class JiraSync(ScanHook):
    def on_status_change(self, finding, old, new):
        if new == "confirmed":
            create_jira_issue(finding)

hook_registry.register("jira-sync", JiraSync())
```

### 5.5 설정 오버레이

```yaml
# /etc/opensast/overlay.yaml
llm:
  provider: anthropic
  max_concurrency: 8
rate_limit_per_minute: 120
```

```bash
export OPENSAST_OVERLAY_CONFIG=/etc/opensast/overlay.yaml
```

1단계 중첩 섹션은 `섹션_키` 로 평탄화된다 (`llm.provider` → `llm_provider`).
`Settings` 에 없는 키는 경고 후 무시된다 — 오타가 조용히 삼켜지지 않는다.
환경변수가 오버레이보다 우선한다.

### 5.6 프론트엔드 테마 오버라이드

```bash
cp /path/to/custom/logo.svg frontend/public/logo.svg
docker compose build frontend
```

---

## 6. 배포 프로파일

### 6.1 Local (개발자 워크스테이션)

```bash
pip install -e '.[dev]'
export OPENSAST_PROFILE=local
opensast serve --reload
```

SQLite 파일 DB (Postgres 선택), 보안 기본값 완화, docs 노출.

### 6.2 Docker Compose (팀/온프레미스)

```bash
cp .env.example .env
docker compose up --build
```

`docker-compose.yml` 이 api·worker 양쪽에 `OPENSAST_PROFILE=docker` 를 명시한다.
6개 서비스(api/worker/postgres/redis/ollama/frontend) + 호스트 bind-mount
`./.opensast-work`.

### 6.3 Cloud (프로덕션)

```bash
OPENSAST_SECRET_KEY=$(openssl rand -hex 32) \
OPENSAST_CORS_ORIGINS=https://sast.corp.com \
OPENSAST_BOOTSTRAP_ADMIN_PASSWORD='<강력한 비밀번호>' \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 스키마는 별도 단계로
docker compose run --rm api alembic upgrade head
```

`docker-compose.prod.yml` 은 위 세 값이 없으면 **기동을 거부**한다. nginx 가 TLS
종료와 `/api` 프록시를 담당하고, `/docs`·`/redoc` 은 비활성이며 rate limit 은
60/min, 로그는 JSON 이다.

---

## 7. 관측성

| 신호 | 구현 | 활성 조건 |
|------|------|-----------|
| 로그 | structlog → stdout(console) / JSON(cloud) | 항상 |
| 감사 | DB `audit_logs` | 항상 |
| 메트릭 | `/metrics` (prometheus_client) | 항상 |
| 트레이스 | OpenTelemetry → OTLP exporter | `OPENSAST_OTEL_ENABLED=true` 또는 `OTEL_EXPORTER_OTLP_ENDPOINT` 설정 시 |
| 헬스체크 | `/health` (liveness) | 항상 |
| 레디니스 | `/ready` — DB · Redis · Celery broker 실제 ping | 항상 |

---

## 8. 알려진 제약

as-built 문서이므로 **지금 없는 것**도 정직하게 적는다. 해결 계획은
[`ROADMAP.md`](ROADMAP.md) 에 있다.

- **rate limit 이 in-memory** — 다중 API 인스턴스 배포에서는 우회 가능
- **CSP 가 `unsafe-inline` 허용** — nonce 기반 미적용
- **엔진·Celery 통합 테스트 부재** — 단위 테스트는 전부 목(mock) 뒤에 있다
- **스캔 취소 불가** — Celery revoke/terminate 경로 없음
- **triage 상한 초과분 미판정** — `triage_max_findings`(기본 2000)를 넘으면
  severity 순으로 자르고, 잘린 사실을 `ScanResult.notes` 에 기록한다
- **시크릿이 환경변수 평문** — 시크릿 매니저 미연동
- **SSRF 방어가 스킴 단위** — 내부 호스트·메타데이터 엔드포인트 차단 없음
- **MOIS 커버리지 46/49** — 미커버 3개(SR1-15, SR5-3, SR5-6)는 C/C++ 메모리
  취약점으로 현재 지원 언어 범위 밖
- **엔진 구성이 확정 결정과 다르다** — [ADR-0001](adr/0001-unified-analysis-pipeline.md)
  이 CodeQL·ESLint 제거와 Joern 대체를 확정(Accepted, 2026-08-26)했으나 **아직
  실행되지 않았다.** 이 문서는 as-built 이므로 현재 있는 것(CodeQL·ESLint 어댑터)
  을 그대로 적는다. 차단 요인은 [ADR-0002](adr/0002-joern-version-pinning.md) 의
  전제 노후화이며 진행 상황은 [`ROADMAP.md`](ROADMAP.md) §2.2 에 있다.
  **상업 진단에서는 CodeQL 을 켜지 않는 편이 안전하다** (GitHub Advanced Security
  라이선스)

---

## 9. 관련 문서

| 알고 싶은 것 | 문서 |
|---|---|
| 왜 그렇게 만들었는가 | [`adr/`](adr/README.md) |
| 무엇을 할 것인가 | [`ROADMAP.md`](ROADMAP.md) |
| 어떻게 쓰는가 | [`guide/`](guide/README.md) |
| 그때는 어땠는가 | [`reviews/`](reviews/) |
