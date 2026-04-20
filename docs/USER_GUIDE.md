# OpenSAST 사용자 가이드

> **최신 업데이트 기준**: 2026-04-17 · 버전 0.5.0
>
> 이 문서는 OpenSAST 전체 기능을 **설치·설정·사용·확장** 관점에서 상세히 설명한다.
> 기능이 변경·추가·제거될 때마다 본 가이드도 함께 갱신된다.

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [설치](#2-설치)
3. [설정 (환경변수)](#3-설정-환경변수)
4. [CLI 레퍼런스](#4-cli-레퍼런스)
5. [REST API 레퍼런스](#5-rest-api-레퍼런스)
6. [분석 파이프라인](#6-분석-파이프라인)
7. [분석 엔진 상세](#7-분석-엔진-상세)
8. [MOIS 49개 항목 카탈로그 + 다중 레퍼런스](#8-mois-49개-항목-카탈로그)
9. [커스텀 룰 작성](#9-커스텀-룰-작성)
10. [LLM 오탐 필터링 + 자연어 검색](#10-llm-오탐-필터링)
11. [리포트 포맷](#11-리포트-포맷)
12. [웹 프론트엔드](#12-웹-프론트엔드)
13. [인증 및 RBAC](#13-인증-및-rbac)
14. [데이터베이스 스키마](#14-데이터베이스-스키마)
15. [테스트](#15-테스트)
16. [트러블슈팅](#16-트러블슈팅)
17. [변경 이력](#17-변경-이력)
18. [상용 솔루션 SAST 대비 기능 비교](#18-상용-솔루션-sast-대비-기능-비교)
19. [엔터프라이즈 기능 (이슈 워크플로 · 게이트 · 감사)](#19-엔터프라이즈-기능)
20. [확장 / 커스터마이징 가이드](#20-확장--커스터마이징-가이드)
21. [관측성 (Prometheus · OpenTelemetry · 구조화 로깅)](#21-관측성)
22. [멀티테넌시 (Organization 기반 데이터 격리)](#22-멀티테넌시)

---

## 1. 프로젝트 개요

**OpenSAST**는 행정안전부 「소프트웨어 보안약점 진단가이드(2021)」 **구현단계 49개
보안약점**을 커버하는 오픈소스 정적분석(SAST) 오케스트레이터다.

### 핵심 특징

- **다중 엔진**: Opengrep(Semgrep CE), Bandit, ESLint, gosec, SpotBugs+FSB, CodeQL 통합
- **2-Pass 분석**: 빠른 1차 패턴 매칭(~30초/PR) + 심층 2차 시맨틱 분석
- **LLM 후처리**: Ollama/Gemma(로컬) · Anthropic Claude(클라우드)로 오탐 확률·판정 근거·조치 방안 자동 생성 (원본 Finding은 **절대 제거하지 않음**)
- **CWE ↔ MOIS 매핑**: 49개 항목을 CWE ID·카테고리·권장 엔진과 함께 단일 카탈로그로 관리
- **확장 가능한 룰**: YAML 기반 Opengrep 룰, CodeQL 쿼리 지원
- **다양한 리포트**: SARIF 2.1.0, HTML, Excel(감리용), PDF

---

## 2. 설치

### 2.0 지원 OS 매트릭스

| 등급 | OS | 실행 방법 | 상태 |
|------|-----|-----------|------|
| **Tier 1 — 완전 지원** | Linux x86_64 / arm64 (Ubuntu 22.04+, Debian 12+, RHEL 9+) | 로컬 pip 또는 Docker Compose | ✅ CI 정기 검증 |
| **Tier 1 — 완전 지원** | macOS (Apple Silicon / Intel) | Docker Compose 권장 | ✅ CI 정기 검증 |
| **Tier 2 — 권장 경로** | **Windows 10/11 + WSL2** | WSL 안에서 Docker Compose | ✅ CI smoke 검증, 상세 가이드: [docs/install-windows-wsl2.md](install-windows-wsl2.md) |
| **Tier 3 — Best-effort** | macOS 네이티브 pip 설치 | `brew install pango cairo` 후 `pip install -e '.[dev]'` | 엔진 바이너리는 별도 수동 설치 필요 |
| **Unsupported** | Windows 네이티브 | — | Semgrep/WeasyPrint/Celery prefork 호환성 문제로 **지원하지 않음**. WSL2 사용 권장 |
| **Unsupported** | FreeBSD/OpenBSD | — | 공식 엔진 바이너리 없음 |

> **결론**: macOS·Linux 는 네이티브/Docker 양쪽 지원, Windows 는 **WSL2 + Docker
> Desktop** 을 통해서만 지원합니다. 상세 설치 가이드는
> [install-windows-wsl2.md](install-windows-wsl2.md) 참조.

### 2.1 로컬 개발 환경

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

주요 의존성(`pyproject.toml`):
- `fastapi`, `uvicorn[standard]`, `celery`, `redis`
- `pydantic[email]`, `pydantic-settings`, `email-validator`
- `sqlalchemy`, `alembic`, `psycopg2-binary`
- `typer`, `rich`
- `anthropic`, `httpx`
- `jinja2`, `openpyxl`, `weasyprint`
- `python-jose[cryptography]`, `bcrypt>=4.1`
- `python-multipart`

### 2.2 Docker Compose (전체 스택)

```bash
cp .env.example .env
docker compose up --build
```

기동되는 서비스:

| 서비스 | 포트 | 설명 |
|--------|------|------|
| `api` | 8000 | FastAPI 애플리케이션 (`/docs` OpenAPI) |
| `worker` | — | Celery 워커 (스캔 비동기 실행) |
| `frontend` | 8080 | React + Vite 개발 서버 |
| `postgres` | 5432 | 결과 영구 저장소 |
| `redis` | 6379 | Celery 브로커 + 캐시 + 분산 rate limit |
| `ollama` | 11434 | 로컬 LLM(Gemma 등) |

스캔 업로드/소스 트리는 프로젝트 루트의 `.opensast-work/` 를 api·worker 가
bind-mount 로 공유한다(오브젝트 스토어 불필요). 프로젝트 폴더를 삭제하면
스토리지도 함께 제거되어 생명주기가 일치한다.

> **v0.5.0**: Dockerfile이 multi-stage 빌드로 전환되었고, non-root 사용자(`opensast`)
> 로 실행되며, `HEALTHCHECK`가 내장되어 있다.

### 2.3 최초 로그인 계정

API 서버가 처음 기동되면 `ensure_bootstrap_admin()`이 자동으로 관리자 계정을
생성한다. 이미 동일 이메일 계정이 있으면 건드리지 않는다.

| 이메일 | 비밀번호 |
|--------|----------|
| `admin@opensast.local` | `opensast-admin` |

**운영 환경**에서는 반드시 `OPENSAST_BOOTSTRAP_ADMIN_EMAIL`,
`OPENSAST_BOOTSTRAP_ADMIN_PASSWORD` 환경변수로 기본값을 덮어쓴 후 기동하세요.

---

## 3. 설정 (환경변수)

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

## 4. CLI 레퍼런스

설치 후 `opensast` 명령이 제공된다(`pyproject.toml` 의 `[project.scripts]`).

### 4.1 `opensast scan`

디렉터리를 스캔하고 SARIF 결과를 저장한다.

```bash
opensast scan <PATH> [OPTIONS]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-o, --output` | `opensast-result.sarif` | SARIF 출력 경로 |
| `--json` | *(없음)* | 도메인 JSON 추가 출력 |
| `--second-pass/--no-second-pass` | `true` | CodeQL/SpotBugs 2차 Pass |
| `--triage/--no-triage` | `true` | LLM 오탐 필터링 |
| `--language` | 자동 감지 | 언어 힌트(`java`, `python`, …) |

**예시**

```bash
# 1차 Pass만, LLM 비활성
opensast scan ./my-service --no-second-pass --no-triage

# 전체 Pass + JSON 덤프
opensast scan ./my-service --json result.json
```

스캔 완료 후 Rich 테이블로 **엔진별 / MOIS ID별 탐지 건수**를 출력한다.

### 4.2 `opensast list-mois`

행안부 49개 항목을 ID·한글명·분류·CWE·심각도 표로 출력한다. 카탈로그 자가진단용
로도 사용되며, 항목이 49개가 아니면 예외를 발생시킨다.

### 4.3 `opensast engines`

`rules/opengrep`, `semgrep`, `bandit`, `eslint`, `gosec`, `spotbugs`, `codeql` 바이너리가
PATH에 존재하는지 표시한다.

### 4.4 `opensast init-db`

DB 스키마를 생성하고 기본적으로 부트스트랩 관리자를 시드한다.

```bash
opensast init-db                   # 스키마 + admin 시드
opensast init-db --no-seed-admin   # 스키마만
```

### 4.5 `opensast serve`

내장 Uvicorn으로 API 서버를 실행한다.

```bash
opensast serve --host 0.0.0.0 --port 8000 --reload
```

### 4.6 `opensast report`

이미 생성된 SARIF 파일에서 HTML/Excel 리포트를 변환한다(DB 없이 동작).

```bash
opensast report result.sarif --html out.html --excel out.xlsx
```

---

## 5. REST API 레퍼런스

FastAPI 앱은 `opensast.api.app:app`에서 제공되며 OpenAPI는 `/docs`에서 확인할 수 있다.

### 5.1 공용

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/health` | 헬스체크 |
| GET | `/ready` | 레디니스 프로브 (DB + Redis + Celery broker ping) |
| GET | `/metrics` | Prometheus 메트릭 (요청 수, 지연시간, 스캔 통계) |

### 5.2 인증 (`/api/auth`)

| 메서드 | 경로 | 설명 | 역할 |
|--------|------|------|------|
| POST | `/api/auth/login` | 이메일·비밀번호로 JWT 발급 | public |
| POST | `/api/auth/refresh` | Refresh token으로 새 토큰 쌍 발급 | 인증 필요 |
| POST | `/api/auth/users` | 사용자 생성 | `admin` |

**로그인 요청/응답**

```http
POST /api/auth/login
{ "email": "admin@opensast.local", "password": "opensast-admin" }

200 { "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer", "role": "admin" }
```

**토큰 갱신**

```http
POST /api/auth/refresh
Authorization: Bearer <refresh_token>

200 { "access_token": "eyJ...", "refresh_token": "eyJ...", "token_type": "bearer", "role": "admin" }
```

인증은 `Authorization: Bearer <token>` 헤더로 수행된다.

### 5.3 프로젝트 (`/api/projects`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/projects` | 프로젝트 목록 |
| POST | `/api/projects` | 프로젝트 생성 |
| GET | `/api/projects/{project_id}` | 단일 조회 |

### 5.4 스캔 (`/api/scans`)

소스 코드 지정 3가지 모드를 모두 지원한다.

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST | `/api/scans` | **서버 경로 모드** — api/worker 가 이미 볼 수 있는 파일시스템 절대경로 |
| POST | `/api/scans/upload` | **ZIP 업로드 모드** — multipart `.zip` 업로드 후 자동 압축 해제 |
| POST | `/api/scans/git` | **Git URL 모드** — worker 가 `git clone --depth=1` 후 스캔 |
| GET | `/api/scans/{scan_id}` | 상태·결과 메타데이터 |
| GET | `/api/scans/{scan_id}/events` | SSE 실시간 스캔 진행 스트리밍 |
| GET | `/api/scans/project/{project_id}` | 프로젝트의 스캔 목록 |

**① 서버 경로 요청 (기존)**

```json
POST /api/scans
{
  "project_id": 1,
  "source_path": "/var/opensast-work/sources/my-service",
  "language_hint": "java",
  "enable_second_pass": true,
  "enable_triage": true
}
```

Docker 구성에서 api·worker 컨테이너는 named volume `opensast-work` 를
`/var/opensast-work` 에 공유 마운트하므로 업로드·clone 모드로 만들어진 경로를
동일하게 재사용할 수 있다.

**② ZIP 업로드 (multipart/form-data)**

```bash
curl -X POST http://localhost:8000/api/scans/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "project_id=1" \
  -F "language_hint=python" \
  -F "enable_second_pass=false" \
  -F "enable_triage=false" \
  -F "archive=@./my-service.zip"
```

- 최대 업로드 크기 500 MiB (`_MAX_UPLOAD_BYTES`)
- 확장자는 `.zip` 만 허용
- 압축 해제 시 **zip-slip** 방지 검증(엔트리 경로가 대상 디렉터리를 벗어나면 400)
- 풀린 경로는 `settings.work_dir/sources/<scan_id>/` 이며 스캔 완료 후 디스크에
  남는다 (수동 정리 필요)

**③ Git URL**

```json
POST /api/scans/git
{
  "project_id": 1,
  "git_url": "https://github.com/OWASP/NodeGoat.git",
  "branch": "master",
  "enable_second_pass": true,
  "enable_triage": true
}
```

- URL 스킴 허용: `http://`, `https://`, `ssh://`, `git@…`
- `branch` 미지정 시 원격 기본 브랜치
- `clone_and_scan_task` 가 `git clone --depth 1` 으로 체크아웃 후 스캔, **스캔
  종료 후 체크아웃 디렉터리를 자동 정리**한다 (결과는 DB 에 영구 저장).

**④ SSE 실시간 진행 스트리밍 (v0.5.0)**

```bash
curl -N http://localhost:8000/api/scans/abc123def456/events \
  -H "Authorization: Bearer $TOKEN"
```

`text/event-stream` 으로 스캔 진행 상태(엔진 시작/완료, triage 진행, 최종 결과)를
실시간 스트리밍한다. 프론트엔드에서 `EventSource` 로 구독하여 진행률 바를
업데이트할 수 있다.

### 5.5 Finding (`/api/findings`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/findings/scan/{scan_id}` | 스캔의 모든 탐지 결과 |
| GET | `/api/findings/{finding_id}` | 단일 Finding |

### 5.6 리포트 (`/api/reports`)

| 메서드 | 경로 | Content-Type |
|--------|------|---------------|
| GET | `/api/reports/{scan_id}/sarif` | `application/sarif+json` |
| GET | `/api/reports/{scan_id}/html` | `text/html` |
| GET | `/api/reports/{scan_id}/excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |

### 5.7 MOIS 카탈로그 (`/api/mois`)

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/api/mois/items` | 49개 항목 목록(ID, 한글명, 분류, CWE, 심각도, 권장 엔진) |

---

## 6. 분석 파이프라인

`opensast.orchestrator.pipeline.ScanPipeline` 이 메인 오케스트레이터다.

```
[소스 루트]
     │
     ▼
┌────────────────────────────┐
│ 1차 Pass (고속 패턴 매칭)   │
│ opengrep / bandit /         │
│ eslint  / gosec             │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────┐
│ 2차 Pass (심층 시맨틱)      │
│ codeql / spotbugs           │
└──────────────┬─────────────┘
               ▼
   merge_findings() 중복 제거
               │
               ▼
┌────────────────────────────┐
│ 3단계 LLM Triage            │
│ Triager.triage()            │
│  → TriageResult 부착(원본   │
│     Finding은 보존)         │
└──────────────┬─────────────┘
               ▼
           ScanResult
```

### 핵심 포인트

- **엔진 바이너리가 없으면 스킵**: `EngineUnavailable` 예외를 파이프라인이 잡아서 해당 엔진만 제외한다. 설치된 엔진 조합만으로도 동작한다.
- **원본 보존**: LLM이 오탐으로 판정해도 Finding은 삭제되지 않으며, `triage.verdict`만 설정된다. 이는 계획서의 리스크 대응 원칙("LLM은 필터링(제거)에만 사용하지 않는다")을 강제한다.
- **중복 제거**: `opensast.sarif.merge.merge_findings()`는 `finding_id`(해시) 및 `(파일, 라인, CWE)` 조합을 키로 사용하며, `_ENGINE_PRIORITY`에 따라 우선 엔진을 남긴다. 동일 위치에서 중복 시 severity가 더 높은 쪽을 유지한다(v0.5.0에서 LOW가 MEDIUM을 이기던 비교 버그 수정).
- **2nd Pass 조건**: `--engines` 로 엔진을 명시 지정해도 그 안에 `codeql`/`spotbugs`가 포함되면 2nd pass가 실행된다.
- **Celery 견고성**: 태스크별 `autoretry_for`/`retry_backoff` 설정, `soft_time_limit`/`time_limit` 분리, Redis pubsub 기반 진행률 추적이 v0.5.0에서 추가되었다.

---

## 7. 분석 엔진 상세

`opensast/engines/` 하위에 각 어댑터가 구현되어 있다. 공통 인터페이스는
`Engine` 추상 클래스(`engines/base.py`)이며, 모두 SARIF 출력을 받아
`findings_from_sarif()`로 도메인 모델로 변환한다.

| 엔진 | 클래스 | 언어 | Pass | 실행 방식 |
|------|--------|------|------|-----------|
| **Opengrep/Semgrep** | `OpengrepEngine` | Java, Python, JS/TS, Go, PHP, Ruby, … | 1차 | `semgrep scan --config rules/opengrep --sarif-output …` |
| **Bandit** | `BanditEngine` | Python | 1차 | `bandit -r <root> -f sarif` |
| **ESLint** | `EslintEngine` | JS/TS | 1차 | `eslint --format @microsoft/eslint-formatter-sarif` |
| **gosec** | `GosecEngine` | Go | 1차 | `gosec -fmt=sarif ./...` (cwd=소스 루트) |
| **SpotBugs + FindSecBugs** | `SpotbugsEngine` | Java, Kotlin, Scala | 2차 | `.class` 디렉터리 존재 시 `spotbugs -sarif -output …` |
| **CodeQL** | `CodeqlEngine` | Java, Kotlin, Python, JS/TS, Go, C/C++ | 2차 | `codeql database create` → `codeql database analyze <pack>` |

### 7.1 등록·선택

- `opensast/engines/registry.py` 의 `ENGINE_CLASSES`, `FIRST_PASS_ENGINES`, `SECOND_PASS_ENGINES` 가 단일 출처다.
- `available_engines()` 는 바이너리 존재 여부를 확인하여 CLI `opensast engines`에서 표시된다.

### 7.2 SpotBugs 특이사항

SpotBugs는 바이트코드 분석기이므로 `.class` 디렉터리가 필요하다.
`build/classes`, `target/classes`, `out/production` 중 존재하는 것을 자동 탐색하며,
하나도 없으면 로그만 남기고 결과는 빈 리스트로 돌려준다.

### 7.3 CodeQL 특이사항

- 소스 루트에 `pom.xml`/`build.gradle`·`pyproject.toml`·`package.json`·`go.mod`·`CMakeLists.txt` 가 있는지로 언어를 자동 감지한다.
- 사용 쿼리팩: `codeql/java-queries`, `codeql/python-queries`, `codeql/javascript-queries`, `codeql/go-queries`, `codeql/cpp-queries`.
- `rules/codeql/<language>/` 디렉터리에 사용자 쿼리가 있으면 `codeql database analyze` 호출에 함께 전달된다.

---

## 8. MOIS 49개 항목 카탈로그

`opensast/mois/catalog.py`가 **단일 소스**다. 7개 상위 분류와 49개 항목을 정확히 포함한다.

| 분류 | 개수 | 대표 항목 |
|------|------|----------|
| 입력데이터 검증 및 표현 | 18 | SQL 삽입(SR1-1), XSS(SR1-3), 명령어 삽입(SR1-4), SSRF(SR1-11), 역직렬화(SR1-18) |
| 보안기능 | 12 | 하드코드 비밀(SR2-6), 취약한 암호(SR2-4), 인증서 검증 결여(SR2-11) |
| 시간 및 상태 | 2 | TOCTOU(SR3-1), 종료되지 않는 반복(SR3-2) |
| 에러처리 | 3 | 오류메시지 정보노출(SR4-1) |
| 코드오류 | 7 | Null 참조(SR5-1), 자원 누수(SR5-2), Use-After-Free(SR5-3) |
| 캡슐화 | 5 | 디버그 코드 잔존(SR6-2) |
| API 오용 | 2 | DNS 기반 보안 결정(SR7-1), 취약한 API 사용(SR7-2) |

### 조회 API

```python
from opensast.mois.catalog import MOIS_ITEMS, get_item, items_for_cwe

get_item("SR1-1")            # SQL 삽입 항목
items_for_cwe("CWE-89")      # CWE로 역조회 (정수 "89" 도 허용)
```

- 전체 목록은 CLI `opensast list-mois` 또는 API `GET /api/mois/items` 에서도 조회 가능.
- 카탈로그 무결성은 `ensure_49_items()` 헬퍼와 `tests/test_mois_catalog.py`가 보장한다.

---

## 9. 커스텀 룰 작성

### 9.1 Opengrep YAML 룰

위치: `rules/opengrep/{java,python,javascript,go,common}/*.yml`

**메타데이터 규약** (자동 MOIS 매핑용):

```yaml
rules:
  - id: mois-sr1-1-python-sql-fstring
    metadata:
      mois_id: "SR1-1"           # 필수: 행안부 ID
      cwe: "CWE-89"              # 필수: CWE ID
      category: "입력데이터 검증 및 표현"
      severity: "HIGH"
      description: "..."
      remediation: "..."
    languages: [python]
    severity: ERROR
    message: "..."
    patterns:
      - pattern: $CUR.execute(f"...{$X}...")
```

> SARIF 정규화 시 `properties.tags` 에 `mois-SR1-1` 형태 태그가 있거나 `cwe-*` 태그가 있으면 Finding에 자동으로 `mois_id`가 설정된다. 태그가 없어도 CWE ID가 있으면 `items_for_cwe()`로 역매핑된다.

기본 제공 룰 요약:

| 파일 | 다루는 MOIS |
|------|-------------|
| `java/sql-injection.yml` | SR1-1 (JDBC concat, MyBatis `${}`) |
| `java/command-injection.yml` | SR1-4 / SR1-2 |
| `java/xss.yml` | SR1-3 / SR1-17 |
| `java/crypto.yml` | SR2-4 / SR2-8 |
| `java/deserialization.yml` | SR1-18 / SR1-11 |
| `python/injection.yml` | SR1-1 / SR1-4 / SR1-17 / SR1-18 |
| `python/crypto.yml` | SR2-4 / SR2-8 / SR2-11 |
| `javascript/injection.yml` | SR1-3 / SR1-17 / SR1-4 |
| `go/injection.yml` | SR1-4 / SR1-1 |
| `common/secrets.yml` | SR2-6 / SR4-1 / SR6-2 |

### 9.2 CodeQL 쿼리

위치: `rules/codeql/<language>/*.ql`

예시: `rules/codeql/java/toctou.ql`(SR3-1 TOCTOU). 쿼리 헤더 주석에
`@id mois/sr3-1-...`, `@tags mois/sr3-1` 와 같이 MOIS ID를 포함하면
SARIF 결과에 반영되어 자동 매핑된다.

---

## 10. LLM 오탐 필터링

`opensast/llm/triage.py::Triager`가 전체 파이프라인을 수행한다.

### 10.1 동작 흐름

1. **컨텍스트 수집**: 탐지 파일을 열어 `±OPENSAST_LLM_CONTEXT_WINDOW_LINES` 줄(기본 20)을 추출. 파일 접근이 실패하면 SARIF `snippet`만 사용.
2. **프롬프트 조립**: `opensast/llm/prompts.py::SYSTEM_PROMPT` + `USER_TEMPLATE` (한국어, 행안부 용어). 탐지 MOIS ID·CWE·파일·엔진·룰·메시지·코드 컨텍스트를 모두 포함.
3. **LLM 호출**: `build_client()` 가 `OPENSAST_LLM_PROVIDER` 에 따라 `AnthropicClient` / `OllamaClient` / `NoopLLMClient` 를 선택.
4. **결과 파싱**: 응답에서 첫 JSON 객체를 추출하여 `TriageResult`로 변환. 파싱 실패 시 `verdict=needs_review`, `fp_probability=OPENSAST_LLM_DEFAULT_FP_PROBABILITY`(기본 50).
5. **부착**: `Finding.triage` 필드에 저장. **원본 Finding은 삭제되지 않음**.

> **v0.5.0 Triage 개선**: Redis 캐싱(24시간 TTL)으로 동일 코드 패턴 재분석을
> 방지한다. LLM 호출은 `tenacity` 재시도 + 서킷브레이커로 일시 장애에 대응한다.

### 10.2 응답 JSON 스키마

```json
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "fp_probability": 0,
  "rationale": "근거 설명(한국어)",
  "recommended_fix": "조치 방안",
  "patched_code": "수정 예시 코드(선택)"
}
```

### 10.3 프로바이더

| 프로바이더 | 클래스 | 사용 조건 |
|-----------|--------|----------|
| **Anthropic Claude** | `AnthropicClient` | `OPENSAST_ANTHROPIC_API_KEY` 설정 + `anthropic` SDK 설치 |
| **Ollama** | `OllamaClient` | `OPENSAST_OLLAMA_HOST` 접근 가능 + `OPENSAST_OLLAMA_MODEL` pull됨 |
| **Noop** | `NoopLLMClient` | 폴백. 항상 `needs_review`, `fp_probability=50` |

---

## 11. 리포트 포맷

`opensast/reports/__init__.py::build_reports()` 가 한 번에 4가지 아티팩트를 만든다.

| 포맷 | 구현 | 용도 |
|------|------|------|
| **SARIF 2.1.0** | `reports/sarif.py::build_sarif` | 도구 간 상호 운용 |
| **HTML** | `reports/html.py::build_html` + `templates/report.html.j2` | 웹 인터랙티브 리포트 |
| **Excel** | `reports/excel.py::build_excel` | 감리용 3시트 (진단요약/상세결과/49개항목) |
| **PDF** | `reports/pdf.py::build_pdf` | WeasyPrint 기반, 라이브러리 부재 시 HTML 폴백 |

### HTML 섹션

1. 스캔 메타데이터 (ID, 대상, 기간, 상태)
2. 심각도별 건수
3. **49개 항목 커버리지 표** (MOIS ID · 항목명 · 분류 · 탐지 건수)
4. 각 Finding 상세 (심각도 배지, MOIS/CWE, 위치, 코드 스니펫, LLM 판정/조치 방안/수정 코드)

### Excel 시트

- **진단요약**: 스캔 메타
- **상세결과**: 심각도·MOIS·분류·CWE·파일·라인·엔진·룰·메시지·LLM 판정·오탐확률·조치방안
- **49개항목**: 전체 49개 행(0 건 포함), 적합/부적합 열

---

## 12. 웹 프론트엔드

`frontend/` — React 18 + TypeScript + Tailwind CSS + Vite + Recharts +
React Router v6 + Zustand + Axios.

### 12.1 페이지 (총 9개)

| 경로 | 파일 | 설명 |
|------|------|------|
| `/login` | `src/pages/Login.tsx` | 로그인, 기본 admin 계정 안내 박스 |
| `/dashboard` | `src/pages/Dashboard.tsx` | **카드 6개**(총/HIGH/MEDIUM/LOW/프로젝트/스캔), 자연어 검색 박스, 30일 시계열 라인차트, 카테고리 파이차트, TOP10 룰 막대차트, MOIS 49개 커버리지 표 |
| `/issues` | `src/pages/IssueSearch.tsx` | Advanced Issue Filter — severity/engine/status/MOIS/CWE/path glob/text 다중 필터 + 자연어 검색 + 결과 테이블 + 워크플로 액션 |
| `/projects` | `src/pages/Projects.tsx` | 프로젝트 생성, 스캔 큐잉(3-모드: 서버 경로 / ZIP 업로드 / Git URL), 스캔 목록, 프로젝트별 "상세" 링크 |
| `/projects/:id` | `src/pages/ProjectDetail.tsx` | 프로젝트 메타 + 스캔 이력 + **Suppression 규칙 CRUD** + **빌드 게이트 정책 편집/검증** |
| `/rule-sets` | `src/pages/RuleSets.tsx` | 체커 그룹 목록, 신규 생성(엔진 체크박스, 룰 include/exclude, 최소 심각도, default 토글), admin 만 삭제 |
| `/scans/:scanId` | `src/pages/ScanDetail.tsx` | 스캔 카드 + diff 카드(신규/해결/지속/신규HIGH) + 전체/diff 탭 + Finding 테이블 + 리포트 다운로드 링크 |
| `/mois` | `src/pages/MoisCatalog.tsx` | 49개 항목 조회 |
| `/audit` | `src/pages/AuditLog.tsx` | 감사 로그 (admin 전용), 액션 필터 |

### 12.2 공통 컴포넌트

- `src/store/auth.ts` — Zustand + persist 토큰 스토어
- `src/api/client.ts` — Axios 인스턴스 + 도메인 헬퍼(`dashboardApi`, `findingsApi`, `ruleSetsApi`, `suppressionsApi`, `gateApi`, `auditApi`, `scansApi`)
- `src/components/ui/Card.tsx` — `StatCard`, `Panel` 재사용 컴포넌트 (tone 별 색상)
- `src/components/ui/Badge.tsx` — `Badge` + `severityTone()` / `statusTone()` / `statusLabel()` 헬퍼
- `src/components/FindingsTable.tsx` — 심각도/상태 배지, 다중 레퍼런스 배지, 워크플로 액션 버튼(역할 기반), 펼침 시 코드 스니펫·LLM 판정·조치 방안·상태 사유
- `src/components/NlSearchBox.tsx` — 자연어 LLM 검색 박스 (`/api/findings/ask`)
- `src/App.tsx` — Shell 헤더/네비/푸터, `Protected` + `AdminOnly` 라우트 가드, 기본 진입점 `/dashboard`

### 12.3 이슈 워크플로 UI

`FindingsTable` 의 행을 클릭하면 펼쳐지는 상세 영역 하단에 **상태 전이 버튼**이
표시된다. 일반 사용자(`analyst`) 는 자체 전이만, `admin` 은 추가로 승인/거부
액션을 수행할 수 있다(버튼에 `(admin)` 라벨). 클릭 시 사유 입력 prompt 가
뜨며, 상태 변경은 `POST /api/findings/{id}/status` 로 전송되고 응답으로
업데이트된 Finding 이 목록에 즉시 반영된다.

### 12.4 차트 라이브러리

`recharts` 사용. `LineChart`(추이), `BarChart`(TOP 룰), `PieChart`(카테고리)
모두 `ResponsiveContainer` 로 감싸 폭에 따라 자동 리사이즈된다.

### 12.5 Vite 프록시

`vite.config.ts` 는 `/api` 를 `VITE_API_TARGET` 환경변수(기본
`http://localhost:8000`, Docker 에서는 `http://api:8000`) 로 프록시한다.

---

## 13. 인증 및 RBAC

- `opensast/api/security.py`: JWT(HS256, jose) 및 **bcrypt 직접** 해싱 (72바이트 상한 안전 처리, passlib 비사용).
  - **v0.5.0**: JWT에 `iat`(발급 시각)·`jti`(UUID 고유 ID) 클레임 추가.
  - **Refresh token**: `POST /api/auth/refresh`로 새 access+refresh 쌍 발급. 로그인 응답에 `refresh_token` 포함.
- `opensast/api/schemas.py`: 이메일 검증은 `EmailStr` 대신 느슨한 정규식(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)을 사용해 `.local`·`.internal` 등 내부망 도메인을 허용한다. 입력은 자동으로 소문자 정규화된다.
- `opensast/api/deps.py::get_current_user` 가 모든 보호 라우트에 주입된다.
- `require_role("admin", …)` 으로 역할 기반 접근 제어 가능. 기본 역할:
  - `admin` — 전체 권한, 사용자 생성 가능
  - `analyst` — 프로젝트·스캔·Finding 조회/생성
  - `viewer` — (모델 정의됨, 쓰기 엔드포인트는 막혀 있음)
- 토큰 만료: `OPENSAST_ACCESS_TOKEN_EXPIRE_MINUTES` (기본 24시간).
- **Rate limit**: Redis 기반 분산 rate limit. IP 당 분당 요청 수 제한(프로파일별 기본값 상이).
- **CSRF 미들웨어**: cloud 프로파일에서 자동 활성화. 쿠키(`opensast_csrf`) + 헤더(`X-CSRF-Token`) 이중 검증. `/api/auth/login`, `/api/auth/refresh`, `/health`, `/ready`, `/metrics` 는 면제.
- **CSP**: `unsafe-inline` 제거, nonce 기반 CSP로 전환.

### 부트스트랩 관리자

`opensast/db/repo.py::ensure_bootstrap_admin` 이 FastAPI `startup` 이벤트에서
호출된다. 동일 이메일의 사용자가 이미 있으면 아무것도 하지 않는다(기존
비밀번호 보존). `opensast init-db` CLI 에서도 동일 로직을 재사용한다.

---

## 14. 데이터베이스 스키마

`opensast/db/models.py` (SQLAlchemy 2.0 Declarative):

| 테이블 | 주요 컬럼 | 관계 |
|--------|----------|------|
| `users` | `id`, `email`(unique), `hashed_password`, `role`, `is_active` | — |
| `projects` | `id`, `name`(unique), `description`, `repo_url`, `default_language`, `owner_id` | 1:N `scans` |
| `scans` | `id`(12자 hex), `project_id`, `source_path`, `status`, `error`, `started_at`, `finished_at`, `engine_stats`(JSON), `mois_coverage`(JSON) | 1:N `findings` |
| `findings` | `id`, `scan_id`, `finding_hash`, `rule_id`, `engine`, `message`, `severity`, `file_path`, `start_line`, `end_line`, `cwe_ids`(JSON), `mois_id`, `category`, `language`, `snippet`, `raw`(JSON) | 1:1 `triage` |
| `triage_records` | `id`, `finding_id`(unique), `verdict`, `fp_probability`, `rationale`, `recommended_fix`, `patched_code`, `model` | — |

스키마는 `startup` 이벤트에서 `Base.metadata.create_all()` 로 자동 생성된다. 운영
배포 시에는 Alembic 마이그레이션으로 전환하는 것을 권장한다.

> **v0.5.0 복합 인덱스**: Finding(`scan_id+severity`, `scan_id+mois_id`,
> `scan_id+status`), Scan(`project_id+status`, `started_at DESC`),
> AuditLog(`action+created_at`), SuppressionRule(`project_id+kind`) 총 7개
> 복합 인덱스가 추가되어 대규모 데이터 조회 성능이 개선되었다.

---

## 15. 테스트

### 15.1 백엔드 (pytest)

```bash
. .venv/bin/activate
pytest -q
```

현재 **백엔드 150+ · 프론트엔드 26 = 총 176+ 테스트** 통과. CI에서 `pytest-cov`
커버리지 리포트, `mypy` 타입 체크, `pip-audit` 보안 감사가 자동 실행된다.

#### 단위 테스트

| 파일 | 커버리지 |
|------|----------|
| `tests/test_mois_catalog.py` | 49개 항목 수, 카테고리 분포, CWE 역조회, ID 유일성 |
| `tests/test_sarif_parser.py` | SARIF 파싱, MOIS 매핑, 엔진 우선순위 병합, 직렬화 라운드트립 |
| `tests/test_engine_registry.py` | 엔진 레지스트리, 가용성, 바이너리 부재 시 파이프라인 정상 종료 |
| `tests/test_llm_triage.py` | Noop Triager 결과 부착, JSON 추출기 관용성 |
| `tests/test_reports.py` | SARIF/HTML/Excel 생성 (한글 섹션, XLSX 시그니처) |
| `tests/test_bootstrap_admin.py` | admin 시드 멱등성, 기존 계정 미덮어쓰기 |
| `tests/test_scan_upload.py` | ZIP 안전 압축 해제, zip-slip 거부, Git URL 스킴 검증 |
| `tests/test_references.py` | OWASP/SANS/PCI 매핑, dedup, 정규화 |
| `tests/test_finding_workflow.py` | 이슈 상태 전이 규칙(자체/관리자) |
| `tests/test_db_migrate.py` | 빈 DB 전체 생성, 누락 컬럼 ALTER, 멱등성 |
| `tests/test_cli.py` | Typer CLI help/list-mois/engines 출력 |

#### 통합 테스트 (FastAPI TestClient + SQLite 인메모리)

| 파일 | 커버리지 |
|------|----------|
| `tests/test_api_auth.py` | 로그인 성공/실패, .local TLD 허용, 잘못된 이메일 422, admin 전용 사용자 생성, 미인증 401 |
| `tests/test_api_projects.py` | CRUD, 중복 이름 409, 미존재 404 |
| `tests/test_api_scans.py` | 큐잉 202, get/list, **diff** (base 자동 선택, 신규/해결/지속 분류, new_high), **source viewer** (경로 탈출 차단, 410 Gone) |
| `tests/test_api_findings.py` | 목록, references 채움(CWE/OWASP/SANS), search 필터 7종(severity/engine/text/mois/path_glob/cwe/include_excluded), **워크플로 전이** (analyst/admin RBAC, 잘못된 상태 422), **자연어 ask** |
| `tests/test_api_dashboard.py` | overview/trends/top-rules/mois-coverage/category-distribution 5종, 시드 데이터와 카운트 일치 검증 |
| `tests/test_api_rule_sets.py` | CRUD, admin 전용, 중복 이름 409, default 단일 강제, default 삭제 차단 |
| `tests/test_api_suppressions.py` | CRUD, 잘못된 kind 422, **persist_scan_result 가 매칭 finding 을 자동 status='excluded' 처리** 검증 |
| `tests/test_api_gate.py` | 정책 upsert (insert/update 분기), passed/blocked, excluded 카운트 제외, disabled 정책 통과 |
| `tests/test_api_audit.py` | 로그인 audit 자동 기록, 로그인 실패 기록, 상태 변경 기록, suppression 생성/삭제 기록, admin 전용 RBAC |
| `tests/test_api_mois_reports_health.py` | /health, MOIS 49 + references, SARIF/HTML/Excel 다운로드 (Content-Type/매직바이트 확인) |

### 15.2 프론트엔드 (Vitest + React Testing Library + MSW)

```bash
# Docker 컨테이너 안에서
docker compose exec frontend npm test

# 또는 호스트에서 (node 설치 후 frontend/ 에서)
cd frontend && npm install && npm test
```

| 파일 | 커버리지 |
|------|----------|
| `src/components/ui/Badge.test.tsx` | Badge tone, severityTone/statusTone/statusLabel 헬퍼 |
| `src/components/ui/Card.test.tsx` | StatCard label/value/hint/tone, Panel title+action+children |
| `src/components/FindingsTable.test.tsx` | 빈 상태, 배지 렌더, 행 펼침 + 코드 스니펫·레퍼런스 링크, **admin/analyst 전이 버튼 표시 차이** |
| `src/components/NlSearchBox.test.tsx` | 자연어 질의 제출 후 결과 표시, 빈 입력 무시 |
| `src/pages/Login.test.tsx` | 기본값 렌더, MSW 모킹 로그인 성공 시 zustand 토큰 저장, 잘못된 비밀번호 시 에러 메시지 |
| `src/pages/Dashboard.test.tsx` | 카드 totals 렌더, MOIS 커버리지 표, TOP 룰 패널 |
| `src/pages/IssueSearch.test.tsx` | 필터 폼 렌더, 검색 버튼 클릭 → MSW 결과 두 건 표시, NL 검색 박스 존재 |
| `src/pages/AuditLog.test.tsx` | 감사 로그 row 렌더, IP 셀 노출 |

#### 프론트엔드 테스트 인프라

- **Vitest 1.6** + **jsdom** 환경
- **@testing-library/react** + **@testing-library/user-event** 로 사용자 인터랙션 시뮬레이션
- **MSW 2.x** 로 `/api/*` 요청을 모킹 (`src/test/msw-server.ts`)
- `src/test/setup.ts` 가 ResizeObserver/matchMedia polyfill, MSW 라이프사이클, localStorage 클린업 처리
- `src/test/test-utils.tsx` 에 `renderWithRouter`, `loginAsAdmin`, `logout` 헬퍼 제공

### 15.3 CI (v0.5.0)

- `pytest-cov` — 커버리지 측정 + 리포트
- `mypy` — 정적 타입 체크
- `pip-audit` — 의존성 보안 취약점 감사
- `dependabot` — GitHub 자동 의존성 업데이트 PR

---

## 16. 트러블슈팅

### SpotBugs가 결과를 내지 않는다
`.class` 디렉터리가 없으면 스킵된다. Gradle/Maven 빌드를 먼저 실행해
`build/classes` 또는 `target/classes` 를 생성하세요.

### CodeQL 쿼리팩 다운로드 실패
`codeql database analyze` 에 `--download` 플래그가 기본으로 포함돼 있다. 오프라인
환경에서는 `codeql pack download codeql/java-queries` 로 사전 캐시하세요.

### WeasyPrint ImportError
pango/cairo 시스템 라이브러리가 필요하다. Docker 이미지에는 포함돼 있으나,
로컬 macOS에서는 `brew install pango cairo` 를 수행하고 venv 재생성이 필요할 수 있다. 실패 시 `reports/pdf.py` 가 HTML 바이트를 폴백으로 반환한다.

### bcrypt / passlib 오류
openSAST는 **bcrypt 를 직접 사용**하므로 passlib 가 설치되어 있어도 영향이 없다.
구버전에서 업그레이드했다면 `pip uninstall passlib` 후 `pip install -e '.[dev]'`
재실행을 권장한다.

### Docker 빌드에서 `openjdk-17-jre-headless` 실패
Debian trixie 이미지는 JDK 17을 제공하지 않는다. Dockerfile은 `openjdk-21-jre-headless` 를 사용한다. 수정한 경우 `docker compose build --no-cache api`.

### 로그인 422 Unprocessable Entity / "이메일 또는 비밀번호를 확인하세요"
증상: 프론트엔드에서 올바른 계정으로 로그인해도 실패. API 로그에
`POST /api/auth/login HTTP/1.1 422 Unprocessable Entity` 가 찍힘.

원인: Pydantic `EmailStr` 이 내부적으로 `email-validator` 라이브러리를 호출하는데,
이 라이브러리는 IANA special-use TLD 인 `.local` 을 "special-use or reserved
name" 으로 거부한다. `admin@opensast.local` 같은 기본 부트스트랩 계정 이메일이
422 로 차단되는 이유다.

해결: `opensast/api/schemas.py` 는 `EmailStr` 대신 느슨한 정규식 검증
(`^[^@\s]+@[^@\s]+\.[^@\s]+$`) 을 사용한다. `LoginRequest`·`UserCreate`·`UserOut`
가 모두 일반 `str` 타입 + `field_validator` 조합으로 정의돼 있으며, 입력값은
소문자로 정규화된다. `.local`·`.internal`·사내 도메인 모두 허용된다.

직접 검증:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@opensast.local","password":"opensast-admin"}'
# → {"access_token":"eyJ...","token_type":"bearer","role":"admin"}
```

### Vite 가 "ready" 로그까지 찍고도 브라우저 응답이 없음 (D-state hang)
증상: `docker compose logs frontend` 에 `VITE v5.x ready in Xms` 가 뜨는데
`curl http://127.0.0.1:8080/` 은 타임아웃, 컨테이너 내부에서 `wget` 도 타임아웃.
`docker compose exec frontend top` 으로 보면 node 프로세스가 **`D` 상태**에
수 GB VSZ 를 차지하고 있다. `netstat -ltn` 의 8080 라인에서 `Recv-Q` 가 0 이
아닌 값(예: 46)이면 확정.

원인: 호스트 `./frontend` 바인드 마운트 + chokidar 폴링 + macOS osxfs 가 파일
스캔으로 I/O 를 포화시켜 Vite 이벤트 루프가 디스크 대기 상태에 묶인다.

해결: 현재 `docker-compose.yml` 에는 바인드 마운트와 `CHOKIDAR_USEPOLLING` 이
모두 제거되어 있고, `vite.config.ts` 에서 `watch.usePolling=false` + node_modules/
dist/.vite 를 워치 대상에서 빼도록 설정되어 있다. 만약 구 설정이 잔존한다면:

```bash
docker compose kill frontend
docker compose rm -f frontend
docker volume rm aisast_opensast-node-modules 2>/dev/null
docker compose up -d --build --force-recreate --no-deps frontend
curl -sS http://127.0.0.1:8080/ -o /dev/null -w "HTTP %{http_code}\n"
```

결과가 `HTTP 200` 이면 정상. 이 모드에서는 HMR 이 없으므로 소스 수정 후에는
반드시 `docker compose build frontend && docker compose up -d frontend` 로
이미지를 리빌드해야 한다.

### `http://localhost:8080` 가 컨테이너에선 떠 있는데 브라우저에서만 안 열림
Vite 로그에 `VITE v5.x ready … Local: http://localhost:8080/` 까지 떴는데도
호스트 브라우저에서 접속이 안 된다면 원인은 대개 둘 중 하나다.

1. **macOS `localhost` IPv6 vs IPv4**: macOS에서는 `localhost` 가 먼저 `::1` 로
   해석되는데 Docker Desktop의 포트 퍼블리시는 IPv4(`0.0.0.0`)에만 적용된다.
   브라우저 주소창에 `http://127.0.0.1:8080/` 를 넣으면 바로 뜬다.
   Compose에는 `ports: "0.0.0.0:8080:8080"` 로 IPv4 바인딩을 명시해 두었다.
2. **API 프록시 타겟**: Vite의 `/api` 프록시는 *Vite 프로세스*가 호출하므로
   컨테이너 내부에서는 `http://localhost:8000` 이 아니라 `http://api:8000` 으로
   가야 한다. `VITE_API_TARGET` 환경변수로 주입되며, `vite.config.ts` 는
   해당 값이 없으면 로컬 `http://localhost:8000` 을 사용한다.

점검 명령:

```bash
# 호스트에서 IPv4로 직접
curl -v http://127.0.0.1:8080/

# 컨테이너 내부에서 자기 자신
docker compose exec frontend wget -qO- http://127.0.0.1:8080 | head

# 포트 퍼블리시 확인 — "0.0.0.0:8080->8080/tcp" 가 보여야 함
docker compose ps frontend
```

### 프론트엔드(http://localhost:8080)가 응답하지 않음
이전 버전 Compose는 `node:20-alpine` 이미지를 그대로 띄우고 바인드 마운트된
호스트 `frontend/` 안에서 `npm install` 을 매 기동 시 실행했다. macOS Docker
Desktop의 osxfs 바인드 마운트가 느려 `npm install` 이 수 분 간 멈춘 것처럼
보이고 로그도 버퍼링되어 출력되지 않는 문제가 있었다.

현재는 **전용 `frontend/Dockerfile`** 이 `node_modules` 를 빌드 타임에 설치하고,
Compose는 `node_modules` 를 named volume(`opensast-node-modules`)으로 올려
호스트 바인드와 충돌을 차단한다. Vite dev 서버는
`--host 0.0.0.0 --port 8080 --strictPort` 로 기동되고 `CHOKIDAR_USEPOLLING=true`
환경변수로 macOS 파일 변경 감지를 안정화한다.

디버깅 절차:

```bash
# 1) 컨테이너 상태
docker compose ps frontend

# 2) 실시간 로그 — "VITE v5.x  ready in Xms" 메시지가 보여야 정상
docker compose logs -f frontend

# 3) 내부에서 Vite 응답 확인
docker compose exec frontend wget -qO- http://127.0.0.1:8080 | head

# 4) node_modules 볼륨이 오염됐을 때 깨끗이 재생성
docker compose down
docker volume rm aisast_opensast-node-modules
docker compose up --build frontend

# 5) 8080 포트가 다른 프로세스에 점유된 경우(strictPort 로 즉시 실패)
lsof -i :8080
```

`package.json` 에 새 의존성을 추가했다면 **반드시** 이미지를 리빌드하세요:

```bash
docker compose build frontend
docker compose up -d frontend
```

### 로그인 403 / 401
부트스트랩 관리자가 생성되었는지 확인: API 로그에 `bootstrap admin created: …`
경고 메시지가 있어야 한다. 존재하지 않으면 `opensast init-db` 를 실행하거나
`docker compose exec api opensast init-db` 를 사용.

---

## 17. 변경 이력

> 기능이 수정/추가/제거될 때마다 본 섹션과 위 상세 섹션을 **동시에** 갱신한다.

### 2026-04-20 — v0.5.1
멀티테넌시(Organization) 지원 추가.

- **Organization 모델**: `organizations` 테이블 신설. slug/name/is_active 관리.
- **organization_id FK**: users, projects, rule_sets, audit_logs 4개 테이블에
  조직 FK 추가. 프로젝트 이름 유일성이 조직 단위로 변경(`uq_project_org_name`).
- **서비스 계층 org scoping**: `BaseService._org_filter` 헬퍼로 자동 조직 필터.
  project/finding/scan/rule_set/suppression/gate 서비스에 적용.
- **JWT `org_id` 클레임**: 로그인/리프레시 토큰에 `org_id` 포함.
- **`require_org_access` 의존성**: 역할 검증 + ActorContext 생성 통합 의존성.
- **Organization CRUD API**: `POST/GET /api/organizations`, `GET /api/organizations/{id}`.
- **Alembic `0003_multitenancy`**: 기존 레코드를 `default-org`(id=1)에 자동 할당.

### 2026-04-17 — v0.5.0
관측성·보안 강화·파이프라인 견고성·DB 성능 최적화 대규모 릴리스.

- **Severity 비교 버그 수정**: `merge.py`에서 LOW가 MEDIUM을 이기던 비교 로직
  버그 수정. 동일 위치 중복 시 더 높은 severity를 유지.
- **2nd Pass 조건 개선**: `--engines` 옵션으로 엔진 명시 지정 시에도 `codeql`,
  `spotbugs`가 포함되면 2nd pass 실행.
- **Dockerfile 하드닝**: multi-stage 빌드, non-root user(`opensast`), HEALTHCHECK
  내장. 이미지 크기 감소 및 컨테이너 보안 강화.
- **Prometheus `/metrics`**: HTTP 요청 수·지연시간, 스캔 수, 탐지 건수 메트릭
  노출. `opensast/api/middleware/prometheus.py`.
- **OpenTelemetry 트레이싱**: `OPENSAST_OTEL_ENABLED=true` +
  `OTEL_EXPORTER_OTLP_ENDPOINT` 설정으로 분산 트레이싱 활성화.
- **JSON 구조화 로깅**: `OPENSAST_LOG_FORMAT=json` 설정 시 ELK/Loki 연동용 JSON
  로그 출력.
- **`/ready` 강화**: DB + Redis + Celery broker ping 통합 헬스체크.
- **JWT `iat`/`jti` 추가**: 토큰 발급 시각 및 고유 ID 클레임.
- **Refresh token**: `POST /api/auth/refresh` 엔드포인트. 로그인 응답에
  `refresh_token` 포함.
- **Redis 기반 분산 rate limit**: 기존 인메모리에서 Redis 백엔드로 전환.
- **CSRF 미들웨어**: cloud 프로파일에서 자동 활성화. 쿠키+헤더 이중 검증.
- **CSP nonce**: `unsafe-inline` 제거, nonce 기반 Content-Security-Policy 전환.
- **DB 복합 인덱스 7개**: Finding(3), Scan(2), AuditLog(1), SuppressionRule(1)
  테이블에 복합 인덱스 추가. 대규모 조회 성능 개선.
- **Celery retry/backoff**: `autoretry_for`, `retry_backoff`, `soft_time_limit`/
  `time_limit` 분리, Redis pubsub 진행률 추적.
- **Triage 개선**: Redis 캐싱(24h TTL), tenacity 재시도, 서킷브레이커.
  `llm_default_fp_probability` 설정값 추가(기본 50).
- **SSE 엔드포인트**: `GET /api/scans/{scan_id}/events` — 실시간 스캔 진행
  스트리밍 (text/event-stream).
- **CI 강화**: `pytest-cov` 커버리지, `mypy` 타입 체크, `pip-audit` 보안 감사,
  `dependabot` 자동 의존성 업데이트.
- **문서**: `CONTRIBUTING.md`, `SECURITY.md` 추가.
- **§3.6 신설**: 관측성 환경변수 테이블.
- **§5.1/5.2/5.4 갱신**: `/metrics`, `/ready`, `/api/auth/refresh`,
  `/api/scans/{id}/events` 엔드포인트 추가.
- **§21 신설**: 관측성 가이드 (Prometheus, OTel, JSON 로깅, readiness probe).

### 2026-04-16 (오후) — 이식성 & CI v0.4.1
OS 종속성 감사 결과를 반영해 이식성을 높이고 CI 매트릭스를 도입.

- **pyproject.toml 메타데이터 보강**: `Development Status`, OS, Python,
  framework, topic, keywords, urls classifiers 추가. 버전 0.4.1. Windows 네이티브
  가 classifier 에 명시적으로 없음을 확인(POSIX 계열만).
- **`work_dir` 기본값 OS 중립화**: `Path(tempfile.gettempdir()) / "opensast-work"`.
  Linux `/tmp`, macOS `/var/folders/...`, Windows `%LOCALAPPDATA%/Temp` 자동.
  Docker compose 는 기존처럼 `/var/opensast-work` 를 명시 override.
- **Celery pool 자동 선택**: `opensast/orchestrator/celery_app.py::recommended_pool()`.
  `sys.platform` 감지해 Windows → `solo`, 그 외 → `prefork`.
  `OPENSAST_CELERY_POOL` 환경변수로 강제 오버라이드 가능.
- **Multi-arch Docker buildx**: `scripts/docker-build-multiarch.sh` — linux/amd64
  + linux/arm64 동시 빌드. `OPENSAST_PUSH=true` 로 레지스트리 푸시.
- **GitHub Actions CI**: `.github/workflows/ci.yml`:
  - backend matrix: ubuntu-24.04 / macos-14 (full pytest) + windows-2022 (smoke
    import + `recommended_pool() == 'solo'` 검증)
  - frontend matrix: 3 OS 모두 vitest + `tsc -b --noEmit`
  - docker-buildx 잡: linux/amd64 + linux/arm64 멀티아키 이미지 빌드
  - self-sast 잡: opensast 가 자기 자신을 스캔, HIGH 발견 시 CI 실패
- **Windows WSL2 설치 가이드** 신규 (`docs/install-windows-wsl2.md`):
  전제·wsl 설치·Docker Desktop 통합·파일시스템 성능·CRLF 주의·트러블슈팅 9개
  섹션. 왜 Windows 네이티브를 지원하지 않는지도 명시.
- **USER_GUIDE §2.0**: 지원 OS 매트릭스 표 추가 (Tier 1/2/3/Unsupported).
- **신규 테스트 2건**: `test_config_work_dir_default.py` (OS 중립 기본값 검증),
  `test_celery_pool_selection.py` (플랫폼 감지 로직, env override).

### 2026-04-16 — 아키텍처 고도화 v0.4.0
애플리케이션·데이터·보안 3개 관점에서 안정성·확장성·유지보수성·편의성을
극대화하는 대규모 리팩토링. 144→162 테스트. 신규 문서 `docs/ARCHITECTURE.md`.

- **플러그인 레지스트리** (`opensast/plugins/`): 5개 카테고리(engines, llm,
  reports, references, hooks) 공통 `Registry` 구현. entry_points + 런타임
  등록 양쪽 지원. 내장 플러그인도 동일 경로로 등록. `OPENSAST_PLUGINS_DISABLED`
  로 선택 비활성.
- **서비스 계층** (`opensast/services/`): `ProjectService`, `ScanService`,
  `FindingService`, `GateService`, `RuleSetService`, `SuppressionService` +
  공통 `BaseService` + `ActorContext`. 라우트는 얇은 HTTP 어댑터로 축소,
  비즈니스 규칙·트랜잭션·감사 로그·RBAC 를 서비스가 책임. 모든 기존 라우트
  재작성(projects/scans/findings/rule_sets/suppressions/gate).
- **확장 훅** (`opensast/hooks.py`): `ScanHook` Protocol + `emit()` 헬퍼.
  파이프라인 `pre_scan/post_scan` + FindingService `on_status_change` 자동
  발행. 한 훅 예외가 다른 훅을 막지 않도록 격리.
- **설정 프로파일** (`opensast/config.py`): `Profile ∈ {local, docker, cloud}`
  + 프로파일별 기본값 번들. `apply_profile_defaults()` + `validate_profile()`.
  cloud 는 docs 비활성·HSTS 강제·secret 강도·CORS allowlist 강제.
- **보안 미들웨어** (`opensast/api/middleware/`):
  - `SecurityHeadersMiddleware` — HSTS, CSP, X-Frame, X-Content-Type,
    Referrer-Policy, Permissions-Policy
  - `RequestSizeMiddleware` — 일반 2 MiB / 업로드 500 MiB 이중 상한
  - `install_rate_limit()` — slowapi 가용 시 IP 기반 분당 제한
  - `install(app, settings)` 공통 진입점으로 프로파일에 맞춰 일괄 적용
- **비밀번호 정책 + 계정 잠금** (`opensast/api/security.py`):
  - `validate_password_policy()` — 최소 12자, 3종 이상 문자, 흔한 비밀번호
    블랙리스트, 연속 동일 문자 4회 금지
  - `register_failed_login()`, `clear_login_failures()`, `is_user_locked()`
  - `users` 테이블에 `failed_attempts`, `locked_until`, `last_login_at` 컬럼
  - 로그인 라우트가 잠김 상태에서 **423 Locked** 반환, 실패마다 감사 로그
- **리소스 오버레이**:
  - `opensast/mois/loader.py::load_mois_catalog()` + `load_reference_overlay()`
  - `OPENSAST_MOIS_CATALOG_PATH` — YAML 로 49개 카탈로그 병합/교체
  - `OPENSAST_REFERENCE_STANDARDS_PATH` — CWE→추가 표준 매핑 (KISA-KSG 등)
  - `opensast/resources/` 에 `mois_catalog.sample.yaml` + `reference_standards.sample.yaml`
    샘플 동봉
- **커스텀 룰 오버레이**: `OPENSAST_CUSTOM_RULES_DIR` — OpengrepEngine 이
  내장 `rules/opengrep` 과 함께 사용자 디렉터리를 `--config` 로 동시 전달.
  업그레이드가 내장 룰만 덮어쓴다.
- **Alembic 마이그레이션**: `alembic.ini`, `alembic/env.py`, `alembic/script.py.mako`,
  `alembic/versions/20260415_0001_initial.py` 스캐폴드. `auto_migrate` 는 dev
  전용 fallback. CLI `opensast db-upgrade` 추가.
- **3-tier 프로덕션 배포**:
  - `deploy/nginx/nginx.conf` — TLS 종료 + 정적 서빙 + `/api` 프록시 + 보안
    헤더 이중 방어 + SPA fallback
  - `frontend/Dockerfile.prod` — 멀티스테이지 (builder + dist 스테이지)
  - `docker-compose.prod.yml` override — nginx 서비스 + cloud 프로파일 환경
    변수 + docs 비활성 + rate 60/min
- **FastAPI 앱 갱신** (`opensast/api/app.py`): `install_middleware()` 호출, 프로파일
  검증 경고, `discover_all()` 로 entry_points 플러그인 발견, `/ready`
  readiness probe 추가, 프로파일에 따라 `/docs` 비활성.
- **테스트 34건 추가** (총 162):
  - `test_plugin_registry.py` (6) · `test_password_policy.py` (9)
  - `test_security_middleware.py` (4) · `test_settings_profile.py` (7)
  - `test_catalog_overlay.py` (3) · `test_hooks.py` (3)
  - `test_account_lockout_e2e.py` (1) · 기존 테스트 2건 경로 조정
- **신규 문서 `docs/ARCHITECTURE.md`**: 3-tier 계층 다이어그램, 플러그인 그룹
  표, 서비스 계층 예시, 배포 프로파일 매트릭스, 보안 모델, 커스터마이징 격리
  원칙, 발전 로드맵.
- **`docs/USER_GUIDE.md` §20 신설**: 확장/커스터마이징 가이드 9개 섹션
  (플러그인, YAML 오버레이, 커스텀 룰, 훅, 프로파일, 서비스 재사용, Alembic,
  프로덕션 배포, 업그레이드 체크리스트).

### 2026-04-15 (심야 — 종합 테스트 스위트 v0.3.1)
구현된 모든 기능을 자동 검증하는 백엔드·프론트엔드 종합 테스트 스위트 추가.

- **백엔드 테스트 통합 픽스처**(`tests/conftest.py`): SQLite 인메모리 + StaticPool +
  의존성 오버라이드(`get_db`) + Celery `.delay` 모킹 + 부트스트랩 admin 시드 +
  `admin_token`/`analyst_token` 헬퍼 + `sample_project` + `sample_scan_with_findings`
  (4건 시드: HIGH 2 + MEDIUM 1 + LOW 1).
- **신규 백엔드 테스트 71건** (총 102 passing):
  - `test_api_auth.py` (7) · `test_api_projects.py` (4)
  - `test_api_scans.py` (7) · `test_api_findings.py` (15)
  - `test_api_dashboard.py` (7) · `test_api_rule_sets.py` (6)
  - `test_api_suppressions.py` (3) · `test_api_gate.py` (6)
  - `test_api_audit.py` (5) · `test_api_mois_reports_health.py` (4)
  - `test_db_migrate.py` (3) · `test_cli.py` (3)
  - persist_scan_result 가 suppression 매칭 시 status='excluded' 자동 처리하는지
    실제 DB 시뮬레이션으로 검증
- **자동 마이그레이션 SQLite 호환성 수정**: `opensast/db/migrate.py` 의 ALTER TABLE
  문에서 `IF NOT EXISTS` 절 제거 (SQLite 미지원). inspector 사전 검사로
  동일 안전성 보장. Postgres/MySQL 에서도 정상 동작.
- **프론트엔드 테스트 도구 도입**: Vitest 1.6 + React Testing Library + MSW 2.x +
  jsdom + @testing-library/user-event. `package.json` 에 `test`, `test:watch`,
  `test:ui` 스크립트 추가.
- **Vitest 설정**: `vitest.config.ts` (jsdom 환경, setup 파일 지정),
  `src/test/setup.ts` (ResizeObserver/matchMedia polyfill, MSW 라이프사이클,
  localStorage 클린업), `src/test/msw-server.ts` (모든 핵심 엔드포인트 모킹),
  `src/test/test-utils.tsx` (renderWithRouter, loginAsAdmin 헬퍼).
- **신규 프론트엔드 테스트 26건** (8 파일):
  - `Badge.test.tsx` (5) · `Card.test.tsx` (4) · `FindingsTable.test.tsx` (5)
  - `NlSearchBox.test.tsx` (2) · `Login.test.tsx` (3) · `Dashboard.test.tsx` (3)
  - `IssueSearch.test.tsx` (3) · `AuditLog.test.tsx` (1)
- **검증**: `pytest -q` → **102 passed**. `docker compose exec frontend npm test` →
  **8 test files | 26 tests passed**.
- **§15 전면 재작성**: 백엔드 단위/통합 테스트 표 + 프론트엔드 테스트 표 +
  테스트 인프라 설명.

### 2026-04-15 (밤 — 웹 UI 전면 고도화 v0.3.0)
백엔드 v0.2.0 에서 만든 11개 신규 엔드포인트를 모두 사용할 수 있도록 React UI
를 전면 재설계. 9개 페이지 구성, 새 차트 라이브러리, 워크플로 액션 통합.

- **추가 의존성**: `recharts ^2.12.7` (대시보드 차트). `package.json` 갱신,
  `frontend/Dockerfile` 빌드 타임에 `npm install` 로 포함.
- **API 클라이언트 전면 확장**: `frontend/src/api/client.ts` — 13개 도메인 타입
  (`Severity`, `FindingStatus`, `Reference`, `Finding`, `MoisItem`,
  `DashboardOverview`, `TrendPoint`, `TopRule`, `MoisCoverage`,
  `CategoryDistribution`, `RuleSet`, `Suppression`, `GatePolicy`, `AuditLog`,
  `ScanDiff`) + 7개 도메인 헬퍼 객체(`dashboardApi`, `findingsApi`,
  `ruleSetsApi`, `suppressionsApi`, `gateApi`, `auditApi`, `scansApi`).
- **Dashboard 페이지** (`/dashboard`): 카드 6개 + 자연어 검색 + 30일 시계열
  라인차트 + 카테고리 파이차트 + TOP10 룰 막대차트 + MOIS 49개 항목 커버리지
  표(스크롤). Recharts `ResponsiveContainer` 로 반응형.
- **Issue Search 페이지** (`/issues`): scan_id, project_id, severity[],
  engine[], status[], mois_id[], cwe[], path_glob, text 필터 폼 + 자연어
  검색 박스 + 결과 테이블. 모든 결과는 워크플로 액션 가능.
- **NL Search 박스** (`src/components/NlSearchBox.tsx`): 인디고 그라데이션
  배경, "상용 솔루션 에 없는 차별화 기능" 표시, 결과 미리보기.
- **FindingsTable 재설계**: 심각도/상태 배지, 다중 레퍼런스 배지(상위 3개 +
  더보기), 펼침 시 코드 스니펫 + 레퍼런스 링크 + LLM 판정 + 상태 사유 +
  **상태 전이 버튼 그리드**. 자체/관리자 전이를 분리 표시(`(admin)` 라벨).
  사용자 prompt 로 사유 입력, 변경 즉시 부모 콜백으로 행 갱신.
- **RuleSets 페이지** (`/rule-sets`): 체커 그룹 목록 + 신규 생성 폼(엔진
  체크박스, include/exclude 룰, 최소 심각도, default 토글). admin 만 삭제·생성.
- **ProjectDetail 페이지** (`/projects/:id`): 프로젝트 메타 카드 + 최근 스캔
  10건 + Suppression 규칙 CRUD(경로/함수/룰 종류 선택, 사유 입력) + 빌드 게이트
  정책 폼(max HIGH/MEDIUM/LOW/new HIGH) + 즉시 게이트 체크 버튼 + 결과 패널.
- **AuditLog 페이지** (`/audit`, admin 전용): 액션 드롭다운 필터 + 시각/사용자/
  액션/대상/IP/상세 컬럼 테이블. 행위별 색상 배지.
- **ScanDetail 재설계**: 스캔 카드 + diff 카드 4개(신규/해결/지속/신규HIGH,
  신규 HIGH 0 이면 ok 톤) + 전체/diff 탭 + 리포트 다운로드 링크. diff 탭에서는
  신규/해결을 별도 패널에 분리 노출.
- **공통 UI 컴포넌트**: `Card.tsx`(`StatCard` tone 5종, `Panel` 재사용),
  `Badge.tsx`(`Badge` tone 7종, `severityTone/statusTone/statusLabel` 헬퍼).
- **App shell 재설계**: 헤더에 6개 메뉴(대시보드/이슈 검색/프로젝트/체커
  그룹/49개 항목/감사 로그-admin), 활성 탭 하이라이트, role 표시, max-w-screen-2xl
  중앙 정렬, `AdminOnly` 라우트 가드. 기본 진입점 `/dashboard` 로 변경.
- **검증**: `docker compose build frontend && up -d --force-recreate frontend`
  후 12개 신규 모듈(App, Dashboard, IssueSearch, RuleSets, ProjectDetail,
  AuditLog, ScanDetail, FindingsTable, NlSearchBox, Card, Badge, client) 모두
  Vite lazy-compile HTTP 200 OK. recharts 의존성 정상 로드. `/api` 프록시 200.

### 2026-04-15 (저녁 — 상용 솔루션 대비 엔터프라이즈 고도화 v0.2.0)
스패로우 SAST/SAQT 사용설명서(202쪽) 를 분석한 뒤 격차를 메우는 대규모 기능
릴리스. 새 라우터 5개, 새 DB 테이블 5개, 새 스키마 12개, 새 테스트 9개.

- **다중 레퍼런스 매핑**: `opensast/mois/references.py` — CWE Top 25(SANS 2023),
  OWASP Top 10 2021, PCI DSS v4.0 핵심 요구사항을 CWE ID 기반으로 자동 역매핑.
  `/api/mois/items` 와 `/api/findings/*` 응답이 `references[]` 배지를 반환.
- **이슈 상태 워크플로**: Finding 에 `status / status_reason / reviewed_by /
  reviewed_at` 컬럼 추가. 상태 전이는 `new → confirmed/exclusion_requested/
  fixed`, 관리자만 `excluded/rejected` 승인. `/api/findings/{id}/status`,
  자동 감사 로그 기록. 상용 솔루션 의 '이슈 제외 신청/승인' 워크플로 대응.
- **Advanced Issue Filter**: `/api/findings/search` — severity·engine·status·
  mois_id·cwe·path_glob·text 다중 필터, 페이지네이션, 기본적으로 excluded 제외.
- **자연어 이슈 검색 (OpenSAST 차별화)**: `/api/findings/ask` — 한국어 질의를
  LLM 이 필터 JSON 으로 변환해 검색. LLM 부재 시 키워드 fallback. 상용 솔루션 에
  없는 기능.
- **대시보드 통계 API**: `/api/dashboard/{overview,trends,top-rules,
  mois-coverage,category-distribution}` — 카드/시계열/TOP 룰/49개 항목
  커버리지/카테고리 분포. 프론트가 차트로 렌더할 수 있는 정규화된 응답.
- **체커 그룹(RuleSet)**: `rule_sets` 테이블 + `/api/rule-sets` CRUD. 프로젝트는
  `rule_set_id` FK 로 한 개 그룹 참조. 엔진 화이트리스트, 규칙 include/exclude,
  최소 심각도, 단일 default 강제. 상용 솔루션 '체커 그룹' 대응.
- **경로/함수/룰 제외 규칙**: `suppression_rules` 테이블 + `/api/projects/
  {id}/suppressions`. 스캔 영구 저장 시 `repo.persist_scan_result` 가 자동
  fnmatch 매칭으로 `status=excluded` 처리하며 `status_reason` 에 사유 기록.
- **이전 분석 비교 (diff)**: `/api/scans/{id}/diff?base={prev}` — `finding_hash`
  기반 신규/해결/지속 분류, base 미지정 시 직전 완료 스캔 자동 선택, 신규 HIGH
  카운트 별도 계산. 상용 솔루션 '이전 결과 비교' 탭 대응.
- **CI/CD 빌드 게이트(이관 제어)**: `gate_policies` 테이블 + `/api/gate/policy`
  upsert + `/api/gate/check` 판정. HIGH/MEDIUM/LOW 임계값, `max_new_high`
  (이전 스캔 대비), `block_on_triage_fp_below` 등. CI 파이프라인이 `passed`
  필드를 보고 머지 차단. 상용 솔루션 '이관 제어' 대응.
- **소스 파일 뷰어**: `/api/scans/{id}/source?path=…` — 스캔 작업 디렉터리 내
  파일 내용을 반환(경로 탈출 차단, 512KB 상한, 큰 파일은 truncated). 상용 솔루션
  '소스 코드 창' 대응. 스캔 디렉터리가 정리된 경우 410 Gone.
- **감사 로그**: `audit_logs` 테이블 + `/api/admin/audit` (admin 전용) +
  `repo.record_audit()` 헬퍼. 로그인/로그인 실패/이슈 상태 변경/제외 규칙
  생성·삭제 자동 기록. user_id, action, target_type, target_id, detail JSON,
  IP, timestamp.
- **DB 스키마 5개 신설**: `rule_sets`, `suppression_rules`, `gate_policies`,
  `audit_logs`, 그리고 Project 에 `rule_set_id` FK 추가. `Base.metadata.create_all`
  이 자동 마이그레이션.
- **신규 라우터 5개**: `dashboard`, `rule_sets`, `suppressions`, `gate`, `audit`.
  총 라우트 42개로 확장.
- **신규 테스트**: `test_references.py` (5건), `test_finding_workflow.py` (4건)
  → 총 31 passing.
- **신규 §18, §19 추가** (상용 솔루션 비교 매트릭스, 엔터프라이즈 기능 가이드).
- **자동 컬럼 마이그레이션**: `opensast/db/migrate.py::auto_migrate()` — 모델과 실제 DB 컬럼을 SQLAlchemy `inspector` 로 비교해 누락 컬럼을 `ALTER TABLE … ADD COLUMN IF NOT EXISTS` 로 자동 추가. NULLABLE 또는 default 가 있는 경우만 안전 처리. API startup 이벤트가 호출. 향후 모델 변경에도 컨테이너 재빌드만으로 스키마가 따라간다 (Alembic 도입 전 임시 메커니즘).
- **검증(end-to-end)**: 기존 Postgres 데이터 유지한 채 5개 컬럼(`projects.rule_set_id`, `findings.status/status_reason/reviewed_by/reviewed_at`) 자동 ALTER 확인. dashboard/overview · mois-coverage(4/49=8.2%) · findings/search?severity=HIGH · 이슈 상태 전이(new→confirmed, reviewer 기록) · gate policy upsert · gate check(passed=true) 모두 200 OK.

### 2026-04-15 (오후 — 소스 입력 UX)
- **스캔 소스 입력 3-모드**: 기존 서버 경로 단일 입력은 Docker 환경에서 "내 PC의 경로를 왜 못 넣지?" 혼란을 유발했다. 이제 다음 3개 엔드포인트가 공존:
  - `POST /api/scans` — 서버 경로 (기존)
  - `POST /api/scans/upload` — 멀티파트 `.zip` 업로드, 500 MiB 상한, zip-slip 방지 압축 해제, 풀린 경로를 `source_path` 로 사용
  - `POST /api/scans/git` — `git clone --depth 1` 후 스캔, 완료 시 체크아웃 자동 정리. URL 스킴 검증(`http`/`https`/`ssh`/`git@`).
- **공유 볼륨**: `opensast-work` named volume 신설. api·worker 가 `/var/opensast-work` 로 동일 마운트. `OPENSAST_WORK_DIR=/var/opensast-work` 환경변수 주입.
- **Celery 태스크**: `clone_and_scan_task` 추가. 실패/크래시 시 `shutil.rmtree` 로 디렉터리 정리 후 `repo.mark_scan_failed`.
- **Pydantic 스키마**: `GitScanCreate` 신설 (URL 스킴 화이트리스트). `ScanCreate` 는 그대로.
- **프론트엔드**: `Projects.tsx` 전면 개편 — 서버 경로 / ZIP 업로드 / Git URL 3-탭, 파일 picker, 언어 힌트·2차 Pass·Triage 토글, 에러 표시, 재사용 가능한 `Tab` 컴포넌트. HTML 리포트 다운로드 링크도 노출.
- **테스트**: `test_scan_upload.py` 추가 (정상 압축 해제, zip-slip 거부, Git URL 검증) → 총 22 passing.
- **검증(end-to-end)**: `curl /api/scans/upload` 로 Python 샘플 zip 업로드 → Opengrep+Bandit 합쳐 5 findings 탐지 (`mois-sr1-4-python-shell-true` 포함). `/api/scans/git` 으로 `OWASP/NodeGoat.git` clone 태스크 수신/실행 확인.
- **§5, §12, §15, §16 업데이트**.

### 2026-04-15
- **Frontend Docker 분리**: 전용 `frontend/Dockerfile` (node:20-alpine, 빌드 타임 `npm install`) 추가. `docker-compose.yml` 프론트엔드 서비스가 `build:` 를 사용하도록 전환.
- **Vite 기동 플래그**: `--host 0.0.0.0 --port 8080 --strictPort` 고정. `vite.config.ts` 에 `server.host='0.0.0.0'`, `strictPort`, `hmr.clientPort=8080` 추가.
- **API 프록시 타겟**: `VITE_API_TARGET` 환경변수로 주입(로컬=기본 `http://localhost:8000`, Docker=`http://api:8000`).
- **포트 바인딩**: `ports: "0.0.0.0:8080:8080"` 로 IPv4 고정(IPv6 `::1` 해석 이슈 방지).
- **FindingsTable**: `React.Fragment` + `key` 사용으로 교체(무키 프래그먼트 경고 제거).
- **Vite D-state hang 수정 (중요)**: 호스트 `./frontend` 바인드 마운트 + `CHOKIDAR_USEPOLLING=true` + macOS osxfs 조합이 Vite 노드 프로세스를 **D-state(uninterruptible I/O wait)** 로 묶어 TCP 연결은 수락하지만 HTTP 응답이 멈추는 현상이 확인됨 (`Recv-Q=46`, `%VSZ=603%`). 해결:
  - `docker-compose.yml` 프론트엔드 서비스에서 `volumes:` (바인드 마운트 + `opensast-node-modules`) **제거**. 이미지에 구운 소스를 그대로 사용 (HMR 없음).
  - `CHOKIDAR_USEPOLLING` 환경변수 삭제.
  - `vite.config.ts` 의 `server.watch.usePolling=false` + `ignored: ['**/node_modules/**','**/dist/**','**/.vite/**']` 로 워치 범위 축소.
  - `healthcheck` 제거 (실패한 헬스체크가 정체된 wget 프로세스를 계속 쌓아 상황 악화).
  - 소스 수정 후에는 `docker compose build frontend && docker compose up -d frontend` 로 재빌드.
- **검증**: `curl http://127.0.0.1:8080/` → HTTP 200, 570 bytes, 71ms. `http://localhost:8080/` 및 `http://127.0.0.1:8080/` 양쪽 정상 응답 확인.
- **트러블슈팅 §16**: "Vite가 ready 로그까지 찍고도 브라우저 응답이 없음 (D-state I/O wait)" 케이스 추가.
- **로그인 422 수정 (중요)**: Pydantic `EmailStr` → `email-validator` 가 `.local` TLD 를 special-use 로 거부하여 기본 부트스트랩 계정 `admin@opensast.local` 로 422 실패. `opensast/api/schemas.py` 의 `LoginRequest`·`UserCreate`·`UserOut` 을 일반 `str` + `field_validator` 기반 정규식 검증으로 교체하고 입력 이메일을 소문자 정규화. §13 인증 섹션과 §16 트러블슈팅에 반영. `curl http://127.0.0.1:8000/api/auth/login` / `curl http://127.0.0.1:8080/api/auth/login` 양쪽에서 HTTP 200 JWT 발급 확인.

### 2026-04-14
- **Init**: 초기 버전 0.1.0 릴리스 — 카탈로그(49), 엔진 어댑터(6), SARIF 파이프라인, LLM Triage(3 프로바이더), FastAPI+JWT+RBAC, Celery 워커, React UI, SARIF/HTML/Excel/PDF 리포트, Docker Compose 스택.
- **Docker**: Debian trixie 호환을 위해 `openjdk-17-jre-headless` → `openjdk-21-jre-headless` 로 변경.
- **Packaging**: `pyproject.toml` 의 `readme` 를 `README.md` 로 변경하고 Dockerfile `COPY` 단계에 포함.
- **Auth**: passlib 제거, **bcrypt 직접 사용**으로 전환. 72바이트 상한 안전 처리.
- **Bootstrap**: API `startup` 이벤트에서 `ensure_bootstrap_admin()` 자동 실행. 기본 계정 `admin@opensast.local / opensast-admin`. env: `OPENSAST_BOOTSTRAP_ADMIN_EMAIL/PASSWORD/DISPLAY_NAME`.
- **CLI**: `opensast init-db --seed-admin/--no-seed-admin` 옵션 추가.
- **Frontend**: 로그인 페이지에 부트스트랩 계정 안내 배지 추가, 기본 입력값 프리셋.
- **Tests**: 부트스트랩 시드/미덮어쓰기 검증 2건 추가 → 총 19 passing.

---

## 18. 상용 솔루션 SAST 대비 기능 비교

스패로우 SAST/SAQT 사용설명서(202쪽) 분석 후 작성한 비교 매트릭스. ✓ = 완전
지원, ◐ = 부분 지원, ✗ = 미지원. ★ 표시는 **OpenSAST 가 상용 솔루션 대비 우위**.

### 18.1 분석·룰

| 기능 | 상용 솔루션 | OpenSAST | 비고 |
|------|---------|--------|------|
| 다중 엔진 통합 | ✓ (자체) | ✓ (Opengrep, Bandit, ESLint, gosec, SpotBugs+FSB, CodeQL) | OpenSAST 는 6개 OSS 엔진 오케스트레이션 |
| 행안부 보안약점 카탈로그 | ✓ (2019) | ✓ (**2021 최신**) ★ | 49개 항목, 7 카테고리 |
| CWE 매핑 | ✓ | ✓ | 카탈로그 단일 소스 |
| OWASP Top 10 매핑 | ✓ | ✓ (2021) | `references_for_cwe()` |
| SANS/CWE Top 25 | △ | ✓ (2023) ★ | OpenSAST 자동 매핑 |
| PCI DSS 매핑 | ✗ | ✓ ★ | 핵심 요구사항 |
| 커스텀 룰 작성 | ✓ (전용 DSL) | ✓ (Opengrep YAML, CodeQL) | OSS 표준 사용 |
| 1차/2차 Pass 분리 | ✗ | ✓ ★ | 고속 스캔 + 심층 |

### 18.2 이슈 관리 워크플로

| 기능 | 상용 솔루션 | OpenSAST |
|------|---------|--------|
| 이슈 상태 (미확인/확인/제외) | ✓ | ✓ (`new/confirmed/exclusion_requested/excluded/fixed/rejected`) |
| 제외 신청 → 관리자 승인 | ✓ | ✓ (`require_role('admin')`) |
| 승인 단계 1~2 단계 | ✓ | ✓ (단일 단계, 확장 가능) |
| 경로/함수/룰 제외 | ✓ | ✓ (`SuppressionRule` + `path/function/rule` 종류) |
| 이슈 상태 그룹 공유(중복 이슈) | ✓ | ✗ (로드맵) |
| 유사 이슈 추천 | ✓ | ◐ (자연어 검색으로 대체) |
| Active Suggestion (수정 코드) | ✓ | ✓ (LLM `patched_code`) |

### 18.3 대시보드·검색

| 기능 | 상용 솔루션 | OpenSAST |
|------|---------|--------|
| 대시보드 카드 | ✓ | ✓ (`/api/dashboard/overview`) |
| 분석 추이(시계열) | ✓ | ✓ (`/api/dashboard/trends`) |
| 체커 분류 파이차트 | ✓ | ✓ (`/api/dashboard/category-distribution`) |
| TOP 룰 | ✓ | ✓ (`/api/dashboard/top-rules`) |
| 49개 항목 커버리지 | ✗ | ✓ ★ (`/api/dashboard/mois-coverage`) |
| Advanced Issue Filter | ✓ | ✓ (`/api/findings/search`) |
| 자연어 질의 검색 | ✗ | ✓ ★ (`/api/findings/ask`, LLM 기반) |
| 이전 분석 비교(diff) | ✓ | ✓ (`/api/scans/{id}/diff`) |

### 18.4 엔터프라이즈·운영

| 기능 | 상용 솔루션 | OpenSAST |
|------|---------|--------|
| 사용자 RBAC | ✓ (역할/권한 세분화) | ✓ (admin/analyst/viewer) |
| LDAP 인증 공급자 | ✓ | ✗ (로드맵) |
| 감사 로그 | ✓ | ✓ (`audit_logs` + `/api/admin/audit`) |
| Jira/Redmine 연동 | ✓ | ✗ (로드맵, 웹훅 형태로 추가 예정) |
| CI/CD 이관 제어(빌드 게이트) | ✓ | ✓ (`/api/gate/check`) |
| 체커 그룹(RuleSet) | ✓ | ✓ (`/api/rule-sets`) |
| 보고서 템플릿 커스터마이징 | ✓ | ◐ (HTML/Excel/PDF 고정 — 로드맵에 포함) |
| 분산 분석(원격 엔진) | ✓ (에이전트 서버) | ✓ (Celery 워커 N개) |
| 라이선스 관리 UI | ✓ | ✗ (오픈소스 무관) |
| Prometheus 메트릭 / OTel 트레이싱 | ✗ | ✓ ★ |
| SSE 실시간 스캔 진행 | ✗ | ✓ ★ |
| Docker Compose 즉시 실행 | ✗ | ✓ ★ |
| Git URL clone 스캔 | ✗ | ✓ ★ |
| ZIP 업로드 스캔 | ✗ | ✓ ★ |
| LLM 기반 오탐 필터링 | ✗ | ✓ ★★ (핵심 차별화) |
| LLM 자연어 검색 | ✗ | ✓ ★★ |
| 자동 조치 코드 생성 | ✗ | ✓ ★★ (LLM `patched_code`) |
| SARIF 표준 출력 | ✓ | ✓ |

### 18.5 통합·연동

| 기능 | 상용 솔루션 | OpenSAST |
|------|---------|--------|
| Eclipse 플러그인 | ✓ | ✗ (로드맵) |
| IntelliJ 플러그인 | ✓ | ✗ (로드맵) |
| Visual Studio 플러그인 | ✓ | ✗ (로드맵) |
| VS Code 플러그인 | ✓ | ✗ (로드맵) |
| CLI 도구 | ✓ (자체) | ✓ (`opensast scan/serve/...`) |
| REST API | ✓ | ✓ (FastAPI + OpenAPI `/docs`) |
| 인증 | ✓ | ✓ (JWT + bcrypt) |

### 18.6 차별화 한 줄 요약

OpenSAST 는 상용 솔루션 의 모든 핵심 워크플로(상태 관리, 제외 승인, 빌드 게이트,
대시보드, diff, 체커 그룹, 감사 로그) 를 동등 이상으로 제공하면서, **상용 솔루션에
없는** ▲ LLM 오탐 필터링 ▲ LLM 자연어 이슈 검색 ▲ LLM 자동 조치 코드 생성 ▲
Git URL/ZIP 즉시 스캔 ▲ Docker Compose 한 줄 배포 ▲ 행안부 2021 최신 카탈로그
를 추가로 갖춘다. 라이선스는 Apache-2.0.

---

## 19. 엔터프라이즈 기능

### 19.1 이슈 상태 워크플로

```
new ─┬─▶ confirmed ─┬─▶ fixed ─┐
     │              │           │
     │              ▼           │
     ├─▶ exclusion_requested ───┼─▶ (admin) excluded ─┐
     │                          │                     │
     │                          └─▶ (admin) rejected ─┤
     │                                                │
     └─◀────────────────────────────────────────────  ┘
                  (취소·재오픈은 일반 사용자 가능)
```

상태 전이 규칙:

- 일반 사용자: `new ↔ confirmed`, `new → exclusion_requested`, `* → fixed`,
  `exclusion_requested → new` (취소), `fixed → new/confirmed` (재오픈)
- 관리자만: `exclusion_requested → excluded/rejected`, `excluded → new`,
  `* → excluded` (즉시 승인)

```bash
# 상태 변경 (개발자가 확인 처리)
curl -X POST http://localhost:8000/api/findings/123/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"confirmed","reason":"실제 SQL 삽입 확인"}'

# 제외 신청
curl -X POST .../api/findings/123/status -d '{"status":"exclusion_requested","reason":"테스트 코드"}'

# 관리자 승인
curl -X POST .../api/findings/123/status -d '{"status":"excluded","reason":"테스트 케이스 허용"}'
```

### 19.2 Advanced Issue Filter

```bash
curl "http://localhost:8000/api/findings/search?\
project_id=1&\
severity=HIGH&severity=MEDIUM&\
engine=opengrep&engine=bandit&\
mois_id=SR1-1&mois_id=SR1-3&\
status=new&status=confirmed&\
path_glob=src/**/api/*.py&\
text=injection&\
limit=100" \
  -H "Authorization: Bearer $TOKEN"
```

지원 파라미터: `scan_id`, `project_id`, `severity[]`, `engine[]`, `status[]`,
`mois_id[]`, `cwe[]`, `path_glob` (fnmatch), `text` (rule_id/message/file_path
ILIKE), `include_excluded` (기본 false), `limit`/`offset`.

### 19.3 자연어 이슈 검색 (LLM)

```bash
curl -X POST http://localhost:8000/api/findings/ask \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"관리자 인증 없이 호출되는 SQL 삽입 중 HIGH 만 보여줘", "project_id": 1}'
```

내부 동작:
1. LLM(`build_client()`) 이 시스템 프롬프트에 따라 질의를 JSON 필터로 변환
2. 변환된 필터(severity, mois_ids, cwe_ids, statuses, text 등)로 DB 조회
3. LLM 부재/호출 실패 시 `_keyword_fallback()` 키워드 파서로 기본 추출

### 19.4 대시보드

```bash
curl http://localhost:8000/api/dashboard/overview               # 카드 4개
curl http://localhost:8000/api/dashboard/trends?days=30         # 시계열
curl http://localhost:8000/api/dashboard/top-rules?limit=10     # TOP 룰
curl http://localhost:8000/api/dashboard/mois-coverage          # 49개 커버리지
curl http://localhost:8000/api/dashboard/category-distribution  # 카테고리 분포
```

### 19.5 체커 그룹(RuleSet)

```bash
curl -X POST http://localhost:8000/api/rule-sets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MOIS-Strict-Java",
    "description": "Java 프로젝트 행안부 49개 + SpotBugs",
    "enabled_engines": ["opengrep","spotbugs","codeql"],
    "include_rules": [],
    "exclude_rules": ["mois-sr6-2-debug-print"],
    "min_severity": "MEDIUM",
    "is_default": false
  }'
```

### 19.6 경로·함수 제외 규칙

```bash
# tests/ 경로의 모든 탐지 자동 제외
curl -X POST http://localhost:8000/api/projects/1/suppressions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"path","pattern":"**/tests/**","reason":"테스트 코드 허용"}'

# 특정 룰만 비활성
curl -X POST .../suppressions -d '{"kind":"rule","pattern":"mois-sr6-2-debug-print","reason":"개발 단계 허용"}'

# 함수명 기반 제외
curl -X POST .../suppressions -d '{"kind":"function","pattern":"sanitize_html_safe","reason":"내부 검증 함수"}'
```

스캔 영구 저장 시 `repo.persist_scan_result()` 가 자동으로 매칭되는 Finding 의
`status='excluded'`, `status_reason='auto-suppressed by project suppression rule'`
로 처리한다.

### 19.7 이전 분석 비교(diff)

```bash
# 가장 최근 vs 직전 분석 자동 비교
curl http://localhost:8000/api/scans/abc123def456/diff -H "Authorization: Bearer $TOKEN"

# 임의의 base 지정
curl http://localhost:8000/api/scans/abc123def456/diff?base=xyz789 -H "Authorization: Bearer $TOKEN"
```

응답: `new[]`, `resolved[]`, `persistent: int`, `summary: {new, resolved, persistent, new_high}`.
diff 키는 `finding_hash` (rule + engine + file + line + mois 의 SHA1).

### 19.8 CI/CD 빌드 게이트

```bash
# 1) 정책 등록 (최초 1회 또는 변경 시)
curl -X PUT http://localhost:8000/api/gate/policy \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "max_high": 0,
    "max_medium": 50,
    "max_low": 500,
    "max_new_high": 0,
    "block_on_triage_fp_below": 30,
    "enabled": true
  }'

# 2) CI 파이프라인에서 게이트 호출
RESULT=$(curl -sS -X POST http://localhost:8000/api/gate/check \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id":1,"scan_id":"abc123","base_scan_id":"prev999"}')
PASSED=$(echo "$RESULT" | jq .passed)
[ "$PASSED" = "true" ] || { echo "BLOCKED:"; echo "$RESULT"; exit 1; }
```

응답: `{passed, reasons[], counts:{HIGH,MEDIUM,LOW}, new_high}`. `reasons` 가
임계값 위반 사유를 한국어로 반환하므로 CI 로그에 그대로 노출 가능.

### 19.9 소스 파일 뷰어

```bash
curl "http://localhost:8000/api/scans/abc123/source?path=src/api/db.py" \
  -H "Authorization: Bearer $TOKEN"
# {"path":"src/api/db.py","truncated":false,"size":1234,"content":"..."}
```

경로 탈출(`../`) 차단, 512KB 상한, 큰 파일은 `truncated:true` 로 잘라서 반환.
스캔 작업 디렉터리가 정리된 경우 410 Gone.

### 19.10 감사 로그

자동 기록되는 액션(샘플):
- `auth.login`, `auth.login_failed`
- `finding.status_change` (이전/이후 상태, 사유, scan_id, rule_id)
- `suppression.create`, `suppression.delete`

```bash
curl "http://localhost:8000/api/admin/audit?action=finding.status_change&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

권한: `admin` 만 조회 가능. 모든 엔트리에 user_id, IP, timestamp, 상세 JSON 포함.

### 19.11 다중 표준 레퍼런스

`/api/mois/items` 와 `/api/findings/*` 응답의 `references[]` 필드:

```json
[
  {"standard": "CWE", "id": "CWE-89", "title": "CWE-89", "url": "https://cwe.mitre.org/.../89.html"},
  {"standard": "OWASP-2021", "id": "A03", "title": "Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
  {"standard": "SANS-25", "id": "#3", "title": "SANS/CWE Top 25 #3", "url": "https://www.sans.org/top25-software-errors/"},
  {"standard": "PCI-DSS-4.0", "id": "6.2.4", "title": "PCI DSS v4.0 §6.2.4", "url": "https://www.pcisecuritystandards.org/"}
]
```

CWE → OWASP/SANS/PCI 매핑은 `opensast/mois/references.py` 단일 소스에서 관리되며
새 표준을 추가할 때 이 파일만 수정하면 모든 응답에 자동 반영된다. 또한 사용자
YAML 오버레이(§20.2) 로 **코드 수정 없이** KISA-KSG, ISO 27001 등을 추가할 수
있다.

---

## 20. 확장 / 커스터마이징 가이드

OpenSAST 는 **5가지 확장 지점**을 제공한다. 커스터마이징은 코어 패키지 수정 없이
이루어지며, 패키지 업그레이드 시에도 유지된다. 전체 아키텍처 원칙은
[docs/ARCHITECTURE.md](ARCHITECTURE.md) 참조.

### 20.1 플러그인 패키지 (엔진 / LLM / 리포트 / 레퍼런스)

Python entry_points 로 플러그인을 등록하면 `pip install` 만으로 OpenSAST 가 자동
발견한다.

```toml
# my-plugin/pyproject.toml
[project]
name = "opensast-plugin-mycheck"
dependencies = ["opensast>=0.5.0"]

[project.entry-points."opensast.engines"]
mycheck = "aisast_plugin_mycheck:MyCheckEngine"

[project.entry-points."opensast.llm"]
vllm = "aisast_plugin_mycheck:VLLMClient"

[project.entry-points."opensast.hooks"]
jira-sync = "aisast_plugin_mycheck:JiraHook"
```

카테고리 목록:

| entry_point 그룹 | 인터페이스 | 설명 |
|-----------------|-----------|------|
| `opensast.engines` | `Engine` | SAST 분석 엔진 어댑터 |
| `opensast.llm` | `LLMClient` | 오탐 필터링용 LLM 프로바이더 |
| `opensast.reports` | 함수 또는 클래스 | 신규 리포트 포맷 |
| `opensast.references` | dict 반환 함수 | CWE→표준 매핑 공급자 |
| `opensast.hooks` | `ScanHook` | 수명주기 훅 |

런타임 등록도 가능:

```python
from opensast.plugins import engine_registry
engine_registry.register("mysast", MySAST, source="runtime")
```

비활성화:

```bash
OPENSAST_PLUGINS_DISABLED=jira-sync,mycheck docker compose up
```

### 20.2 YAML 리소스 오버레이

**커스텀 MOIS 항목 추가** — 행안부 개정판, 사내 전용 룰 코드:

```yaml
# /etc/opensast/mois_override.yaml
items:
  - id: "SR1-1"
    name_kr: "SQL 삽입 (개정판)"
    name_en: "SQL Injection"
    category: "입력데이터 검증 및 표현"
    cwe_ids: ["CWE-89", "CWE-564"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
  - id: "ORG-SR-101"
    name_kr: "사내 API 키 하드코드"
    category: "보안기능"
    cwe_ids: ["CWE-798"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
```

```bash
OPENSAST_MOIS_CATALOG_PATH=/etc/opensast/mois_override.yaml
```

기존 49개 위에 **병합** 되므로 내장 항목을 보존하면서 추가/교체할 수 있다.
샘플: `opensast/resources/mois_catalog.sample.yaml`.

**커스텀 레퍼런스 표준 추가** — KISA-KSG, ISO 27001, 사내 표준:

```yaml
# /etc/opensast/refs_override.yaml
mappings:
  "CWE-89":
    - standard: "KISA-KSG-2024"
      id: "DB-001"
      title: "데이터베이스 입력 검증 필수"
  "CWE-79":
    - standard: "ISO-27001"
      id: "A.14.2.5"
      title: "Secure system engineering principles"
```

```bash
OPENSAST_REFERENCE_STANDARDS_PATH=/etc/opensast/refs_override.yaml
```

샘플: `opensast/resources/reference_standards.sample.yaml`.

### 20.3 커스텀 룰 디렉터리

Opengrep 룰은 내장 `rules/opengrep/` 과 **같은 레벨로** 사용자 디렉터리를
추가할 수 있다:

```bash
mkdir -p /etc/opensast/my-rules/python
cp my-custom-rule.yml /etc/opensast/my-rules/python/

OPENSAST_CUSTOM_RULES_DIR=/etc/opensast/my-rules \
  docker compose up -d
```

업그레이드 시 내장 룰만 덮어쓰고 `/etc/opensast/my-rules` 는 건드리지 않는다.

### 20.4 확장 훅

Python 코드로 수명주기 이벤트를 구독:

```python
# my_aisast_plugin/hooks.py
from opensast.hooks import hook_registry
from opensast.db import models

class JiraIssueSync:
    def on_status_change(self, finding: models.Finding, old: str, new: str):
        if new == "confirmed":
            create_jira_ticket(finding)

    def post_scan(self, scan_id: str, result):
        if any(f.severity == "HIGH" for f in result.findings):
            send_slack_alert(scan_id, result.findings)

hook_registry.register("jira-sync", JiraIssueSync())
```

지원 이벤트:

| 이벤트 | 시점 | 인자 |
|--------|------|------|
| `pre_scan` | 스캔 시작 직전 | `(scan_id, target)` |
| `post_scan` | 스캔 완료 후 (Triage 포함) | `(scan_id, result)` |
| `pre_persist` | DB 저장 직전 | `(scan_id, result)` |
| `post_persist` | DB 저장 후 | `(scan_id, scan_row)` |
| `on_status_change` | Finding 상태 전이 시 | `(finding, old, new)` |

모든 훅 호출은 격리되어 있어 한 훅의 예외가 다른 훅이나 코어 파이프라인을
멈추게 하지 않는다.

### 20.5 설정 프로파일

배포 환경마다 동일 코드베이스로 기본값을 바꿀 수 있다:

| 프로파일 | 대상 | 주요 차이 |
|----------|------|-----------|
| `local` | 개발자 워크스테이션 | CORS=`*`, docs 활성, rate limit off, 약한 secret 허용 |
| `docker` | 팀/온프렘 Compose | CORS=localhost, rate 100/min, INFO 로그 |
| `cloud` | 프로덕션 클라우드 | **docs 비활성**, **HSTS 강제**, secret 강도 검증, rate 60/min, JSON 로그(`OPENSAST_LOG_FORMAT=json`), CORS allowlist 강제, **CSRF 활성**, **CSP nonce** |

```bash
OPENSAST_PROFILE=cloud \
  OPENSAST_SECRET_KEY=$(openssl rand -hex 32) \
  OPENSAST_CORS_ORIGINS=https://sast.corp.com \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

모든 개별 값은 여전히 `OPENSAST_*` 환경변수로 재정의된다. 프로파일은 **기본값**
만 바꾼다.

### 20.6 서비스 계층 재사용

라우트와 독립된 비즈니스 로직은 `opensast.services` 에 있으므로 Celery 태스크·
CLI·외부 스크립트에서 동일한 API 로 재사용할 수 있다:

```python
from opensast.db.session import session_scope
from opensast.services import ActorContext, ProjectService, ScanService

with session_scope() as session:
    actor = ActorContext(user=None, ip="127.0.0.1")
    project = ProjectService(session, actor).create(name="nightly-scan")
    scan = ScanService(session, actor).queue_from_path(
        project_id=project.id,
        source_path="/build/workspace",
        language_hint="java",
        enable_second_pass=True,
        enable_triage=True,
    )
```

### 20.7 Alembic 마이그레이션

스키마 변경은 Alembic 정식 마이그레이션으로 관리:

```bash
# 새 모델 추가 후
alembic revision --autogenerate -m "add some_table"

# 적용
alembic upgrade head

# 또는 CLI
opensast db-upgrade
```

`auto_migrate` 는 개발용 fallback 으로만 동작하며, 프로덕션에서는 반드시
Alembic 을 사용한다.

### 20.8 프로덕션 배포 (3-tier)

```
 브라우저                  nginx                 FastAPI            Postgres
 ────────   HTTPS   ───▶  (tls종료)  ───▶       (api/worker)  ───▶ (managed)
                           · 정적 서빙            · 서비스계층
                           · /api 프록시         · 플러그인 로드
                           · 보안 헤더           · 감사 로그
```

`docker-compose.prod.yml` override 로 nginx + 정적 빌드 프론트엔드 + cloud
프로파일 API 가 한 번에 올라온다. 자세한 실행 방법은 `ARCHITECTURE.md §6.3`
참조.

### 20.9 업그레이드 체크리스트

패키지 버전을 올릴 때 다음 6가지가 보존되는지만 확인하면 된다 — 모두 환경변수/
볼륨 기반이므로 코드 수정 불필요.

1. `OPENSAST_MOIS_CATALOG_PATH` — 카탈로그 오버레이 YAML 경로
2. `OPENSAST_REFERENCE_STANDARDS_PATH` — 레퍼런스 오버레이 YAML 경로
3. `OPENSAST_CUSTOM_RULES_DIR` — 커스텀 Opengrep 룰 디렉터리
4. 설치된 플러그인 패키지 (`pip list | grep opensast-plugin-`)
5. `docker-compose.override.yml` — 환경변수·볼륨 커스텀
6. DB 데이터 — Alembic 이 호환 마이그레이션 제공

---

## 21. 관측성

v0.5.0에서 Prometheus 메트릭, OpenTelemetry 분산 트레이싱, 구조화 JSON 로깅이
추가되었다.

### 21.1 Prometheus 메트릭

`GET /metrics` 엔드포인트가 Prometheus text format으로 메트릭을 노출한다.

수집되는 주요 메트릭:
- `aisast_http_requests_total` — HTTP 요청 수 (method, path, status)
- `aisast_http_request_duration_seconds` — 요청 지연 시간 히스토그램
- `aisast_scans_total` — 스캔 실행 수 (status)
- `aisast_findings_total` — 탐지 건수 (severity)

Prometheus scrape 설정 예시:

```yaml
scrape_configs:
  - job_name: opensast
    static_configs:
      - targets: ['api:8000']
    metrics_path: /metrics
```

### 21.2 OpenTelemetry 트레이싱

환경변수로 활성화:

```bash
OPENSAST_OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
```

활성화 시 HTTP 요청, Celery 태스크, LLM 호출, DB 쿼리에 span이 자동 부착된다.
Jaeger, Tempo 등 OTLP 호환 백엔드로 수집 가능.

### 21.3 구조화 로깅

```bash
OPENSAST_LOG_FORMAT=json
```

`json` 설정 시 모든 로그가 `{"timestamp":..., "level":..., "message":..., "extra":...}`
형태로 출력되어 ELK/Loki 등 로그 수집 파이프라인과 연동이 용이하다. 기본값은
`console`(사람이 읽기 좋은 형식).

### 21.4 Readiness Probe

`GET /ready` 는 DB 연결, Redis 연결, Celery broker ping을 모두 확인하고, 하나라도
실패하면 503을 반환한다. Kubernetes `readinessProbe`나 로드밸런서 헬스체크에 사용.

```yaml
# Kubernetes 예시
readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## 22. 멀티테넌시

OpenSAST 는 **Organization(조직)** 단위로 데이터를 격리하는 멀티테넌시 모델을 지원한다.
하나의 OpenSAST 인스턴스에서 여러 팀이나 부서가 각자의 프로젝트/룰셋/감사로그를 독립적으로
관리할 수 있다.

### 22.1 Organization 모델

| 필드 | 타입 | 설명 |
|------|------|------|
| `id` | Integer (PK) | 자동 증가 ID |
| `slug` | String(120), unique | URL-safe 식별자 (예: `security-team`) |
| `name` | String(200) | 표시 이름 |
| `is_active` | Boolean | 비활성화 시 소속 사용자 접근 차단 |

### 22.2 조직 스코핑

다음 테이블에 `organization_id` FK가 추가된다:

- **users** -- 사용자가 소속된 조직
- **projects** -- 프로젝트별 조직 귀속. 조직 내에서 프로젝트 이름 유일
- **rule_sets** -- 조직별 체커 그룹
- **audit_logs** -- 조직별 감사 기록

서비스 계층(`BaseService._org_filter`)이 자동으로 현재 사용자의 `organization_id`에
맞는 레코드만 반환한다. `organization_id`가 None인 컨텍스트(슈퍼 관리자 등)는 전체
레코드를 조회할 수 있다.

### 22.3 JWT 토큰

로그인 시 발급되는 JWT에 `org_id` 클레임이 포함된다:

```json
{
  "sub": "user@example.com",
  "role": "analyst",
  "org_id": 1,
  "exp": 1745000000,
  "iat": 1744900000,
  "jti": "abc123...",
  "type": "access",
  "iss": "opensast",
  "aud": "opensast"
}
```

### 22.4 Organization CRUD API

| 메서드 | 경로 | 권한 | 설명 |
|--------|------|------|------|
| `POST` | `/api/organizations` | admin | 조직 생성 |
| `GET` | `/api/organizations` | 인증됨 | 조직 목록 |
| `GET` | `/api/organizations/{org_id}` | 인증됨 | 조직 상세 |

**조직 생성 예시:**

```bash
curl -X POST http://localhost:8000/api/organizations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slug": "security-team", "name": "Security Team"}'
```

### 22.5 Alembic 마이그레이션

`0003_multitenancy` 마이그레이션이 기존 데이터를 `default-org` 조직(id=1)에 자동
할당한다. 업그레이드 시 기존 데이터 유실 없이 멀티테넌시로 전환된다.
