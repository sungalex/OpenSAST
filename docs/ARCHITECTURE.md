# OpenSAST 아키텍처

> 본 문서는 OpenSAST 의 **애플리케이션 / 데이터 / 보안** 3개 관점에서 설계
> 원칙과 구현 상세를 기술한다. 안정성·확장성·유지보수성·편의성을 극대화하기
> 위해 다음 4가지 설계 목표를 따른다.
>
> 1. **플러그인 기반 확장** — 엔진/레퍼런스/리포트/LLM 을 코어 수정 없이 추가
> 2. **3-tier 배포 프로파일** — 로컬 / Docker / Cloud 를 단일 코드베이스로 지원
> 3. **커스터마이징 격리** — 패키지 업그레이드가 사용자 커스텀을 깨지 않음
> 4. **Secure by default** — 인증·권한·네트워크·저장소 전 계층 기본값이 안전

---

## 1. 계층 구조

```
┌─────────────────────────────────────────────────────────────────┐
│                     ① Web Tier (Edge)                           │
│   nginx (TLS terminate · static serve · /api proxy · WAF rules) │
│   └── React SPA (Vite build → static bundle)                    │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼  HTTPS / Authz header
┌─────────────────────────────────────────────────────────────────┐
│                     ② WAS Tier (App Server)                     │
│                                                                 │
│   ┌────────────────────────────────────────────────────────┐    │
│   │  FastAPI Routes  (thin HTTP adapters)                  │    │
│   │     │                                                  │    │
│   │     ▼                                                  │    │
│   │  Service Layer  (business logic, transactions,         │    │
│   │                  audit emission, RBAC enforcement)     │    │
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
│   Celery Workers (scan execution, clone_and_scan)               │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼  SQL / Redis / S3
┌─────────────────────────────────────────────────────────────────┐
│                     ③ Data Tier                                 │
│                                                                 │
│   Postgres           Redis            MinIO / S3        Ollama  │
│   (primary RW)       (queue+cache)    (source storage)  (local) │
└─────────────────────────────────────────────────────────────────┘
```

각 티어는 독립적으로 **수평 확장**되며 서로 다른 노드·컨테이너·클라우드
서비스로 이전할 수 있다. 모든 요청은 ① → ② → ③ 단방향으로 흐른다.

---

## 2. 애플리케이션 아키텍처

### 2.1 라우트 → 서비스 → 레포 3계층

```python
# 라우트는 얇은 어댑터 — Pydantic 검증 + 서비스 호출만
@router.post("/projects")
def create_project(payload, request, db, user):
    return ProjectService(db, actor=user, ip=request.client.host).create(
        payload.name, payload.description
    )

# 서비스는 트랜잭션 경계, 비즈니스 규칙, 감사 로그를 책임
class ProjectService:
    def create(self, name, description) -> Project:
        self._require_unique_name(name)
        project = self.repo.insert(name=name, description=description,
                                   owner_id=self.actor.id)
        self._audit("project.create", project.id, detail={"name": name})
        return project

# 레포는 쿼리 조립만 담당
class ProjectRepo:
    def insert(self, **fields) -> Project: ...
    def find_by_name(self, name) -> Project | None: ...
```

**효과**:
- 라우트 단위 테스트는 서비스 모킹만으로 가능
- 동일한 비즈니스 로직을 CLI·Celery·Webhook 어디서든 재사용
- 감사 로그 기록을 서비스 계층에 집중해 누락 방지

### 2.2 플러그인 레지스트리

모든 확장 포인트는 동일한 `Registry` 패턴으로 관리된다:

```python
registry = Registry[EngineClass]("opensast.engines")

# 내장 등록
registry.register("opengrep", OpengrepEngine)
registry.register("bandit",   BanditEngine)

# 외부 패키지가 entry_points 로 등록 (pip install opensast-plugin-xyz)
# pyproject.toml:
#   [project.entry-points."opensast.engines"]
#   xyz = "aisast_plugin_xyz:XyzEngine"

# 런타임 조회
registry.get("opengrep")
registry.all()
```

플러그인 카테고리:

| 그룹 | entry_point 그룹 | 인터페이스 |
|------|------------------|-----------|
| 분석 엔진 | `opensast.engines` | `Engine` (base.py) |
| LLM 프로바이더 | `opensast.llm` | `LLMClient` |
| 리포트 포맷 | `opensast.reports` | `ReportWriter` |
| 레퍼런스 표준 | `opensast.references` | `ReferenceProvider` |
| 수명주기 훅 | `opensast.hooks` | `ScanHook` |

### 2.3 확장 훅

```python
class ScanHook(Protocol):
    def pre_scan(self, scan_id: str, target: ScanTarget) -> None: ...
    def post_scan(self, scan_id: str, result: ScanResult) -> None: ...
    def on_status_change(self, finding: Finding, old: str, new: str) -> None: ...

# 등록 (entry_points 또는 런타임)
hook_registry.register("jira-sync", JiraIssueHook)
```

커스텀 감사·알림·Jira/Slack 연동을 **코어 수정 없이** 추가할 수 있다.

### 2.4 설정 프로파일

`OPENSAST_PROFILE ∈ {local, docker, cloud}` 으로 기본값 번들을 전환한다.

| 항목 | local | docker | cloud |
|------|-------|--------|-------|
| `cors_origins` | `["*"]` | `["http://localhost:8080"]` | 환경변수 allowlist 강제 |
| `secret_key` 검증 | 경고 | 경고 | **기본값 거부** (32자 이상 강제) |
| `database_url` 기본 | SQLite | Postgres(compose) | 미설정 시 오류 |
| `rate_limit` | off | 100/min | 60/min |
| `log_level` | DEBUG | INFO | INFO + JSON format |
| `enable_docs` | true | true | false |

모든 값은 `OPENSAST_*` 환경변수로 재정의 가능하며, 프로파일은 단지 기본값
번들이다.

---

## 3. 데이터 아키텍처

### 3.1 스키마 관리

- **Alembic** 를 정식 마이그레이션 도구로 도입. `alembic/versions/` 에
  리비전 파일이 버전 관리됨.
- 기존 `opensast/db/migrate.py::auto_migrate()` 는 **개발 전용 fallback** 으로
  축소. 프로덕션에서는 `alembic upgrade head` 를 반드시 실행.
- 모델 변경 → `alembic revision --autogenerate -m "..."` → 리뷰 → 커밋.

### 3.2 Repository 패턴

| 집합(Aggregate) | Repository |
|----------------|-----------|
| User | `UserRepo` |
| Project · Scan · Finding · Triage | `ProjectRepo`, `ScanRepo`, `FindingRepo` |
| RuleSet · Suppression · GatePolicy | `RuleSetRepo`, `SuppressionRepo`, `GatePolicyRepo` |
| AuditLog | `AuditRepo` |

각 Repo 는 단일 SQLAlchemy Session 을 주입받고, **트랜잭션은 서비스 계층
에서만 커밋**한다.

### 3.3 3-Tier 데이터 배포

| 배포 모드 | Postgres | Redis | MinIO | Ollama |
|----------|----------|-------|-------|--------|
| **Local** | SQLite 파일 (`.opensast-work/opensast.db`) 또는 로컬 Postgres | 선택 | 선택 | 선택 |
| **Docker compose** | `postgres:16-alpine` 컨테이너 + named volume | `redis:7-alpine` | `minio:latest` | `ollama:latest` |
| **Cloud** | **관리형 Postgres** (RDS/Cloud SQL/Aurora) | 관리형 Redis (ElastiCache/Memorystore) | 관리형 오브젝트 스토어 (S3/GCS) | **Anthropic API** 또는 GPU 노드 |

연결 문자열만 환경변수로 주입하면 동일 이미지가 세 모드 모두에서 동작한다.

### 3.4 캐싱 전략

| 데이터 | 저장소 | TTL |
|--------|--------|-----|
| MOIS 49 catalog | 프로세스 메모리 (import 시 1회) | 프로세스 수명 |
| 레퍼런스 매핑 | 메모리 | 프로세스 수명 |
| RuleSet, GatePolicy | 메모리 + Redis 무효화 pub/sub | 60초 |
| 스캔 결과 페이지네이션 | Redis | 10분 |
| JWT deny-list | Redis | 토큰 exp 시간까지 |

### 3.5 파일·소스코드 저장

- 업로드된 ZIP 과 git clone 체크아웃은 `OPENSAST_WORK_DIR` 아래 임시 디렉터리.
- 완료된 스캔 결과는 **DB 에만** 보존되며 원본 소스는 클린업된다.
- 장기 보존이 필요한 경우 MinIO/S3 에 SARIF + 리포트를 업로드 (향후).

---

## 4. 보안 아키텍처

### 4.1 인증

- JWT HS256, 수명 24h (환경변수로 조정 가능)
- 비밀번호 해싱: **bcrypt 직접** (passlib 미사용, bcrypt>=4.1 호환)
- 이메일: 느슨한 정규식 + 소문자 정규화 (`.local` 등 내부망 도메인 허용)
- 향후: Refresh token + 로테이션, OIDC/LDAP 연동

### 4.2 계정 보안

| 방어 | 구현 |
|------|------|
| **비밀번호 정책** | 최소 12자, 대·소·숫자·특수 중 3종 이상, 흔한 비밀번호 블랙리스트 |
| **계정 잠금** | 연속 실패 5회 시 15분 잠금 (`users.failed_attempts`, `users.locked_until`) |
| **실패 감사** | 모든 실패 시도가 `audit_logs` 에 기록 (IP 포함) |
| **부트스트랩 경고** | 기본 비밀번호 사용 시 로그 WARNING + 프로덕션 프로파일에서는 변경 강제 |

### 4.3 권한 (RBAC)

세 역할:

| 역할 | 스캔 실행 | 이슈 조회 | 이슈 상태 변경 | 제외 승인 | 체커 그룹 관리 | 감사 로그 |
|------|:-:|:-:|:-:|:-:|:-:|:-:|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `analyst` | ✓ | ✓ | ✓ (제외 승인 제외) | ✗ | ✗ | ✗ |
| `viewer` | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |

확인된 이슈의 `excluded` 전환은 반드시 `admin` 승인을 거친다.

### 4.4 네트워크 / HTTP 보안

| 대책 | 구현 |
|------|------|
| **CORS allowlist** | 프로파일별 기본값, `OPENSAST_CORS_ORIGINS` 환경변수로 재정의 |
| **보안 헤더** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Rate limiting** | `slowapi` — IP·사용자 기준 분당 60~100 (프로파일별) |
| **Request size** | 업로드 500 MiB, 그 외 라우트 1 MiB (미들웨어) |
| **TLS** | Production 프로파일 nginx 에서 HTTPS 종료 (자체서명 또는 Let's Encrypt) |
| **docs 노출** | cloud 프로파일에서 `/docs`, `/redoc` 비활성화 |

### 4.5 입력 검증 & OWASP 자체 방어

- **SQL 삽입**: SQLAlchemy ORM 만 사용, 원시 쿼리 금지
- **Path Traversal**: 소스 뷰어/ZIP 해제에서 `resolve()` + prefix 검증
- **SSRF**: Git URL 스킴 화이트리스트(`http/https/ssh/git@`)
- **XXE**: YAML/XML 파싱 시 `safe_load`, lxml 비사용
- **Deserialization**: pickle 사용 금지, JSON 만
- **오류 메시지 노출**: 내부 예외는 로그로만, 사용자에게는 일반화된 메시지
- **Self-SAST**: CI 파이프라인에서 opensast 가 자기 자신을 스캔해 회귀 차단

### 4.6 감사 & 모니터링

- `audit_logs` 테이블에 로그인/로그인 실패/이슈 상태 변경/제외 생성·삭제/관리자
  액션 기록. IP·user_id·timestamp·detail JSON 포함.
- 로그 포맷: 로컬 `rich`, cloud 프로파일 `JSON` (Datadog/Stackdriver 호환).
- 향후: Prometheus `/metrics` 엔드포인트, OpenTelemetry trace propagation.

---

## 5. 커스터마이징 격리

사용자가 OpenSAST 를 포크하지 않고 커스터마이징할 수 있는 6가지 확장 지점:

### 5.1 커스텀 룰 디렉터리

```bash
export OPENSAST_CUSTOM_RULES_DIR=/etc/opensast/my-rules
```

Opengrep 엔진이 내장 `rules/opengrep/` 과 이 디렉터리를 **동시에** `--config`
로 전달한다. 패키지 업그레이드가 내장 룰만 덮어쓰고 커스텀 룰은 건드리지
않는다.

### 5.2 커스텀 리소스 오버라이드

```bash
export OPENSAST_MOIS_CATALOG_PATH=/etc/opensast/mois_override.yaml
export OPENSAST_REFERENCE_STANDARDS_PATH=/etc/opensast/refs_override.yaml
```

내장 YAML 위에 사용자 YAML 이 **merge** 된다. 행안부 2023 개정판이 나오면
Python 수정 없이 YAML 하나만 배포하면 된다.

### 5.3 플러그인 패키지

```
my-opensast-plugin/
├── pyproject.toml
│   └── [project.entry-points."opensast.engines"]
│       mysonar = "my_aisast_plugin:MySonarEngine"
└── my_aisast_plugin/__init__.py
```

`pip install my-opensast-plugin` 만으로 OpenSAST 가 해당 엔진을 자동 발견.

### 5.4 훅 구독

```python
# my_aisast_plugin/hooks.py
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
  model: claude-opus-4-6
gate_defaults:
  max_high: 0
  max_medium: 100
```

`OPENSAST_OVERLAY_CONFIG=/etc/opensast/overlay.yaml` 환경변수로 로드.

### 5.6 프론트엔드 테마 오버라이드

```bash
cp /path/to/custom/logo.svg frontend/public/logo.svg
OPENSAST_BRAND_NAME="MyCompany SAST" docker compose build frontend
```

---

## 6. 배포 프로파일

### 6.1 Local (개발자 워크스테이션)

```bash
pip install -e '.[dev]'
export OPENSAST_PROFILE=local
opensast serve --reload
```

- SQLite 파일 DB (Postgres 선택)
- Celery 없이 동기 실행 (`OPENSAST_SYNC_MODE=true`)
- 보안 기본값 완화

### 6.2 Docker Compose (팀/온프레미스)

```bash
OPENSAST_PROFILE=docker docker compose up -d
```

- 7개 서비스 (api/worker/postgres/redis/minio/ollama/frontend)
- 이 리포지토리의 기본 구성
- 자체 DNS 로 서비스 이름 사용

### 6.3 Cloud (프로덕션)

```bash
OPENSAST_PROFILE=cloud \
  OPENSAST_DATABASE_URL=postgresql+psycopg2://... \
  OPENSAST_REDIS_URL=rediss://... \
  OPENSAST_CORS_ORIGINS=https://sast.corp.com \
  OPENSAST_SECRET_KEY=$(openssl rand -hex 32) \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

- nginx: TLS 종료 + 정적 서빙 + `/api` 프록시 + 보안 헤더
- 관리형 Postgres / Redis / 오브젝트 스토어 (URL 만 교체)
- 프론트엔드는 production 빌드 (multi-stage Dockerfile)
- `/docs`, `/redoc` 비활성
- rate_limit 60/min, JSON 로그

---

## 7. 관측성

| 신호 | 구현 | 위치 |
|------|------|------|
| 로그 | structlog → stdout (로컬) / JSON (cloud) | 모든 서비스 |
| 감사 | DB `audit_logs` + 장기 보관은 S3 export (향후) | WAS |
| 메트릭 | FastAPI `/metrics` (prometheus_client) | WAS (TODO) |
| 트레이스 | OpenTelemetry HTTP → OTLP exporter | WAS (TODO) |
| 헬스체크 | `/health` (liveness) + `/ready` (readiness, DB/Redis 체크) | WAS |

---

## 8. 발전 로드맵

| Phase | 항목 |
|-------|------|
| ✅ v0.3.1 | 128 테스트, 상용 솔루션 수준 엔터프라이즈 기능 |
| 🚧 v0.4.0 | 본 아키텍처 문서의 모든 항목 (플러그인, 서비스 계층, 프로파일, 보안 미들웨어, 계정 잠금, YAML 카탈로그, 커스텀 오버레이, 확장 훅, Alembic, nginx prod) |
| v0.5.0 | Refresh token, OIDC/LDAP, Redis 캐시 레이어, `/metrics`, OpenTelemetry |
| v0.6.0 | 멀티 테넌시 (organizations), 수평 분산 Celery broker HA, S3 업로드 |
| v1.0.0 | KISA CC 인증 요구사항 반영, 정식 릴리스 |
