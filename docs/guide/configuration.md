# 설정 레퍼런스

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

> **정본 주의**
>
> 이 문서는 `opensast/config.py` 를 **서술**한다. 값이 어긋나면 코드가 정본이다
> ([ADR-0006](../adr/0006-configuration-single-source.md)). 프로파일별 기본값 표는
> [ARCHITECTURE §2.5](../ARCHITECTURE.md#25-설정-프로파일) 가 정본이다.

---

## 설정 (환경변수)

모든 설정은 `opensast/config.py`의 `Settings` 클래스에서 관리되며, 환경변수
접두사는 `OPENSAST_`다. `.env` 파일이 있으면 자동으로 로드된다.

### 3.1 핵심 · 경로

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OPENSAST_DEBUG` | `false` | 디버그 모드 |
| `OPENSAST_RULES_DIR` | `<repo>/rules` | 룰 디렉터리 루트 |
| `OPENSAST_WORK_DIR` | `<cwd>/.opensast-work` | 업로드 소스 · git clone 트리를 저장하는 파일 스토리지. CWD(프로젝트 루트) 하위 숨김 폴더 — 프로젝트 삭제 시 함께 제거 |

### 3.2 데이터베이스 / 큐

| 변수 | 기본값 |
|------|--------|
| `OPENSAST_DATABASE_URL` | `postgresql+psycopg2://opensast:opensast@localhost:5432/opensast` |
| `OPENSAST_REDIS_URL` | `redis://localhost:6379/0` |
| `OPENSAST_CELERY_BROKER_URL` | `redis://localhost:6379/1` |
| `OPENSAST_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` |

### 3.3 인증 · 부트스트랩 관리자

| 변수 | 기본값 |
|------|--------|
| `OPENSAST_SECRET_KEY` | `change-me-in-production-please-32-chars-min` |
| `OPENSAST_ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24시간) |
| `OPENSAST_BOOTSTRAP_ADMIN_EMAIL` | `admin@opensast.local` |
| `OPENSAST_BOOTSTRAP_ADMIN_PASSWORD` | `opensast-admin` |
| `OPENSAST_BOOTSTRAP_ADMIN_DISPLAY_NAME` | `OpenSAST Admin` |

> **v0.5.0**: JWT에 `iat`(발급 시각)·`jti`(고유 ID) 클레임이 추가되었고,
> `POST /api/auth/refresh`로 refresh token 갱신을 지원한다. cloud 프로파일에서는
> CSRF 미들웨어가 자동 활성화되며, rate limit이 Redis 기반 분산 방식으로 동작한다.

### 3.4 LLM

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OPENSAST_LLM_PROVIDER` | `ollama` | `ollama` · `anthropic` · `noop` |
| `OPENSAST_ANTHROPIC_API_KEY` | `None` | Claude API 키 |
| `OPENSAST_ANTHROPIC_MODEL` | `claude-opus-4-6` | 모델 ID |
| `OPENSAST_OLLAMA_HOST` | `http://localhost:11434` | Ollama 엔드포인트 |
| `OPENSAST_OLLAMA_MODEL` | `gemma2:9b` | 로컬 모델 |
| `OPENSAST_LLM_TIMEOUT_SECONDS` | `60` | |
| `OPENSAST_LLM_CONTEXT_WINDOW_LINES` | `20` | 탐지 지점 ±N줄 컨텍스트 |
| `OPENSAST_LLM_DEFAULT_FP_PROBABILITY` | `50` | LLM 호출 실패/파싱 오류 시 기본 오탐 확률(0-100) |

### 3.5 관측성

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OPENSAST_OTEL_ENABLED` | `false` | OpenTelemetry 트레이싱 활성화 (`true`/`1`/`yes`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(없음)* | OTLP 수집기 주소 (예: `http://jaeger:4317`) |
| `OPENSAST_LOG_FORMAT` | `console` | 로그 형식. `json`으로 설정 시 구조화 JSON 로깅 |

### 3.6 엔진 바이너리 경로

PATH에서 발견되지 않으면 해당 엔진은 스킵된다(에러가 아님).

| 변수 | 기본값 |
|------|--------|
| `OPENSAST_OPENGREP_BIN` | `semgrep` |
| `OPENSAST_BANDIT_BIN` | `bandit` |
| `OPENSAST_ESLINT_BIN` | `eslint` |
| `OPENSAST_GOSEC_BIN` | `gosec` |
| `OPENSAST_SPOTBUGS_BIN` | `spotbugs` |
| `OPENSAST_CODEQL_BIN` | `codeql` |

---
