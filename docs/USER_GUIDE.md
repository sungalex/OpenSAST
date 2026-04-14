# aiSAST 사용자 가이드

> **최신 업데이트 기준**: 2026-04-14 · 버전 0.1.0
>
> 이 문서는 aiSAST 전체 기능을 **설치·설정·사용·확장** 관점에서 상세히 설명한다.
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
8. [MOIS 49개 항목 카탈로그](#8-mois-49개-항목-카탈로그)
9. [커스텀 룰 작성](#9-커스텀-룰-작성)
10. [LLM 오탐 필터링](#10-llm-오탐-필터링)
11. [리포트 포맷](#11-리포트-포맷)
12. [웹 프론트엔드](#12-웹-프론트엔드)
13. [인증 및 RBAC](#13-인증-및-rbac)
14. [데이터베이스 스키마](#14-데이터베이스-스키마)
15. [테스트](#15-테스트)
16. [트러블슈팅](#16-트러블슈팅)
17. [변경 이력](#17-변경-이력)

---

## 1. 프로젝트 개요

**aiSAST**는 행정안전부 「소프트웨어 보안약점 진단가이드(2021)」 **구현단계 49개
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
- `minio`, `python-multipart`

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
| `frontend` | 5173 | React + Vite 개발 서버 |
| `postgres` | 5432 | 결과 영구 저장소 |
| `redis` | 6379 | Celery 브로커 + 캐시 |
| `minio` | 9000 / 9001 | 소스·리포트 오브젝트 스토어 |
| `ollama` | 11434 | 로컬 LLM(Gemma 등) |

### 2.3 최초 로그인 계정

API 서버가 처음 기동되면 `ensure_bootstrap_admin()`이 자동으로 관리자 계정을
생성한다. 이미 동일 이메일 계정이 있으면 건드리지 않는다.

| 이메일 | 비밀번호 |
|--------|----------|
| `admin@aisast.local` | `aisast-admin` |

**운영 환경**에서는 반드시 `AISAST_BOOTSTRAP_ADMIN_EMAIL`,
`AISAST_BOOTSTRAP_ADMIN_PASSWORD` 환경변수로 기본값을 덮어쓴 후 기동하세요.

---

## 3. 설정 (환경변수)

모든 설정은 `aisast/config.py`의 `Settings` 클래스에서 관리되며, 환경변수
접두사는 `AISAST_`다. `.env` 파일이 있으면 자동으로 로드된다.

### 3.1 핵심 · 경로

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AISAST_DEBUG` | `false` | 디버그 모드 |
| `AISAST_RULES_DIR` | `<repo>/rules` | 룰 디렉터리 루트 |
| `AISAST_WORK_DIR` | `<repo>/.aisast-work` | 임시 작업 디렉터리 |

### 3.2 데이터베이스 / 큐

| 변수 | 기본값 |
|------|--------|
| `AISAST_DATABASE_URL` | `postgresql+psycopg2://aisast:aisast@localhost:5432/aisast` |
| `AISAST_REDIS_URL` | `redis://localhost:6379/0` |
| `AISAST_CELERY_BROKER_URL` | `redis://localhost:6379/1` |
| `AISAST_CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` |

### 3.3 MinIO

| 변수 | 기본값 |
|------|--------|
| `AISAST_MINIO_ENDPOINT` | `localhost:9000` |
| `AISAST_MINIO_ACCESS_KEY` | `minioadmin` |
| `AISAST_MINIO_SECRET_KEY` | `minioadmin` |
| `AISAST_MINIO_BUCKET` | `aisast-sources` |
| `AISAST_MINIO_SECURE` | `false` |

### 3.4 인증 · 부트스트랩 관리자

| 변수 | 기본값 |
|------|--------|
| `AISAST_SECRET_KEY` | `change-me-in-production-please-32-chars-min` |
| `AISAST_ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24시간) |
| `AISAST_BOOTSTRAP_ADMIN_EMAIL` | `admin@aisast.local` |
| `AISAST_BOOTSTRAP_ADMIN_PASSWORD` | `aisast-admin` |
| `AISAST_BOOTSTRAP_ADMIN_DISPLAY_NAME` | `aiSAST Admin` |

### 3.5 LLM

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AISAST_LLM_PROVIDER` | `ollama` | `ollama` · `anthropic` · `noop` |
| `AISAST_ANTHROPIC_API_KEY` | `None` | Claude API 키 |
| `AISAST_ANTHROPIC_MODEL` | `claude-opus-4-6` | 모델 ID |
| `AISAST_OLLAMA_HOST` | `http://localhost:11434` | Ollama 엔드포인트 |
| `AISAST_OLLAMA_MODEL` | `gemma2:9b` | 로컬 모델 |
| `AISAST_LLM_TIMEOUT_SECONDS` | `60` | |
| `AISAST_LLM_CONTEXT_WINDOW_LINES` | `20` | 탐지 지점 ±N줄 컨텍스트 |

### 3.6 엔진 바이너리 경로

PATH에서 발견되지 않으면 해당 엔진은 스킵된다(에러가 아님).

| 변수 | 기본값 |
|------|--------|
| `AISAST_OPENGREP_BIN` | `semgrep` |
| `AISAST_BANDIT_BIN` | `bandit` |
| `AISAST_ESLINT_BIN` | `eslint` |
| `AISAST_GOSEC_BIN` | `gosec` |
| `AISAST_SPOTBUGS_BIN` | `spotbugs` |
| `AISAST_CODEQL_BIN` | `codeql` |

---

## 4. CLI 레퍼런스

설치 후 `aisast` 명령이 제공된다(`pyproject.toml` 의 `[project.scripts]`).

### 4.1 `aisast scan`

디렉터리를 스캔하고 SARIF 결과를 저장한다.

```bash
aisast scan <PATH> [OPTIONS]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-o, --output` | `aisast-result.sarif` | SARIF 출력 경로 |
| `--json` | *(없음)* | 도메인 JSON 추가 출력 |
| `--second-pass/--no-second-pass` | `true` | CodeQL/SpotBugs 2차 Pass |
| `--triage/--no-triage` | `true` | LLM 오탐 필터링 |
| `--language` | 자동 감지 | 언어 힌트(`java`, `python`, …) |

**예시**

```bash
# 1차 Pass만, LLM 비활성
aisast scan ./my-service --no-second-pass --no-triage

# 전체 Pass + JSON 덤프
aisast scan ./my-service --json result.json
```

스캔 완료 후 Rich 테이블로 **엔진별 / MOIS ID별 탐지 건수**를 출력한다.

### 4.2 `aisast list-mois`

행안부 49개 항목을 ID·한글명·분류·CWE·심각도 표로 출력한다. 카탈로그 자가진단용
로도 사용되며, 항목이 49개가 아니면 예외를 발생시킨다.

### 4.3 `aisast engines`

`rules/opengrep`, `semgrep`, `bandit`, `eslint`, `gosec`, `spotbugs`, `codeql` 바이너리가
PATH에 존재하는지 표시한다.

### 4.4 `aisast init-db`

DB 스키마를 생성하고 기본적으로 부트스트랩 관리자를 시드한다.

```bash
aisast init-db                   # 스키마 + admin 시드
aisast init-db --no-seed-admin   # 스키마만
```

### 4.5 `aisast serve`

내장 Uvicorn으로 API 서버를 실행한다.

```bash
aisast serve --host 0.0.0.0 --port 8000 --reload
```

### 4.6 `aisast report`

이미 생성된 SARIF 파일에서 HTML/Excel 리포트를 변환한다(DB 없이 동작).

```bash
aisast report result.sarif --html out.html --excel out.xlsx
```

---

## 5. REST API 레퍼런스

FastAPI 앱은 `aisast.api.app:app`에서 제공되며 OpenAPI는 `/docs`에서 확인할 수 있다.

### 5.1 공용

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/health` | 헬스체크 |

### 5.2 인증 (`/api/auth`)

| 메서드 | 경로 | 설명 | 역할 |
|--------|------|------|------|
| POST | `/api/auth/login` | 이메일·비밀번호로 JWT 발급 | public |
| POST | `/api/auth/users` | 사용자 생성 | `admin` |

**로그인 요청/응답**

```http
POST /api/auth/login
{ "email": "admin@aisast.local", "password": "aisast-admin" }

200 { "access_token": "eyJ...", "token_type": "bearer", "role": "admin" }
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
| GET | `/api/scans/project/{project_id}` | 프로젝트의 스캔 목록 |

**① 서버 경로 요청 (기존)**

```json
POST /api/scans
{
  "project_id": 1,
  "source_path": "/var/aisast-work/sources/my-service",
  "language_hint": "java",
  "enable_second_pass": true,
  "enable_triage": true
}
```

Docker 구성에서 api·worker 컨테이너는 named volume `aisast-work` 를
`/var/aisast-work` 에 공유 마운트하므로 업로드·clone 모드로 만들어진 경로를
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

`aisast.orchestrator.pipeline.ScanPipeline` 이 메인 오케스트레이터다.

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
- **중복 제거**: `aisast.sarif.merge.merge_findings()`는 `finding_id`(해시) 및 `(파일, 라인, CWE)` 조합을 키로 사용하며, `_ENGINE_PRIORITY`에 따라 우선 엔진을 남긴다.

---

## 7. 분석 엔진 상세

`aisast/engines/` 하위에 각 어댑터가 구현되어 있다. 공통 인터페이스는
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

- `aisast/engines/registry.py` 의 `ENGINE_CLASSES`, `FIRST_PASS_ENGINES`, `SECOND_PASS_ENGINES` 가 단일 출처다.
- `available_engines()` 는 바이너리 존재 여부를 확인하여 CLI `aisast engines`에서 표시된다.

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

`aisast/mois/catalog.py`가 **단일 소스**다. 7개 상위 분류와 49개 항목을 정확히 포함한다.

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
from aisast.mois.catalog import MOIS_ITEMS, get_item, items_for_cwe

get_item("SR1-1")            # SQL 삽입 항목
items_for_cwe("CWE-89")      # CWE로 역조회 (정수 "89" 도 허용)
```

- 전체 목록은 CLI `aisast list-mois` 또는 API `GET /api/mois/items` 에서도 조회 가능.
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

`aisast/llm/triage.py::Triager`가 전체 파이프라인을 수행한다.

### 10.1 동작 흐름

1. **컨텍스트 수집**: 탐지 파일을 열어 `±AISAST_LLM_CONTEXT_WINDOW_LINES` 줄(기본 20)을 추출. 파일 접근이 실패하면 SARIF `snippet`만 사용.
2. **프롬프트 조립**: `aisast/llm/prompts.py::SYSTEM_PROMPT` + `USER_TEMPLATE` (한국어, 행안부 용어). 탐지 MOIS ID·CWE·파일·엔진·룰·메시지·코드 컨텍스트를 모두 포함.
3. **LLM 호출**: `build_client()` 가 `AISAST_LLM_PROVIDER` 에 따라 `AnthropicClient` / `OllamaClient` / `NoopLLMClient` 를 선택.
4. **결과 파싱**: 응답에서 첫 JSON 객체를 추출하여 `TriageResult`로 변환. 파싱 실패 시 `verdict=needs_review`, `fp_probability=50`.
5. **부착**: `Finding.triage` 필드에 저장. **원본 Finding은 삭제되지 않음**.

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
| **Anthropic Claude** | `AnthropicClient` | `AISAST_ANTHROPIC_API_KEY` 설정 + `anthropic` SDK 설치 |
| **Ollama** | `OllamaClient` | `AISAST_OLLAMA_HOST` 접근 가능 + `AISAST_OLLAMA_MODEL` pull됨 |
| **Noop** | `NoopLLMClient` | 폴백. 항상 `needs_review`, `fp_probability=50` |

---

## 11. 리포트 포맷

`aisast/reports/__init__.py::build_reports()` 가 한 번에 4가지 아티팩트를 만든다.

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

`frontend/` — React 18 + TypeScript + Tailwind CSS + Vite.

### 12.1 페이지

| 경로 | 파일 | 설명 |
|------|------|------|
| `/login` | `src/pages/Login.tsx` | 로그인, 기본 admin 계정 안내 박스 |
| `/projects` | `src/pages/Projects.tsx` | 프로젝트 생성, 스캔 큐잉(3-모드: 서버 경로 / ZIP 업로드 / Git URL), 스캔 목록 |
| `/scans/:scanId` | `src/pages/ScanDetail.tsx` | 스캔 메타 + 엔진/MOIS 집계 + Finding 테이블 |
| `/mois` | `src/pages/MoisCatalog.tsx` | 49개 항목 조회 |

### 12.2 구성 요소

- `src/store/auth.ts` — Zustand + persist 토큰 스토어 (`aisast-auth` localStorage 키)
- `src/api/client.ts` — Axios 인스턴스, `/api` 베이스, 401 발생 시 자동 로그아웃
- `src/components/FindingsTable.tsx` — 심각도 배지, LLM 판정 배지, 클릭 시 코드 스니펫·조치 방안 확장
- `src/App.tsx` — `Protected` 라우트 가드, Shell 헤더/푸터

### 12.3 Vite 프록시

`vite.config.ts` 는 `/api` 를 `http://localhost:8000` 으로 프록시한다. Docker
Compose 사용 시 `frontend` 컨테이너에서 `api` 서비스로 그대로 연결된다.

---

## 13. 인증 및 RBAC

- `aisast/api/security.py`: JWT(HS256, jose) 및 **bcrypt 직접** 해싱 (72바이트 상한 안전 처리, passlib 비사용).
- `aisast/api/schemas.py`: 이메일 검증은 `EmailStr` 대신 느슨한 정규식(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)을 사용해 `.local`·`.internal` 등 내부망 도메인을 허용한다. 입력은 자동으로 소문자 정규화된다.
- `aisast/api/deps.py::get_current_user` 가 모든 보호 라우트에 주입된다.
- `require_role("admin", …)` 으로 역할 기반 접근 제어 가능. 기본 역할:
  - `admin` — 전체 권한, 사용자 생성 가능
  - `analyst` — 프로젝트·스캔·Finding 조회/생성
  - `viewer` — (모델 정의됨, 쓰기 엔드포인트는 막혀 있음)
- 토큰 만료: `AISAST_ACCESS_TOKEN_EXPIRE_MINUTES` (기본 24시간).

### 부트스트랩 관리자

`aisast/db/repo.py::ensure_bootstrap_admin` 이 FastAPI `startup` 이벤트에서
호출된다. 동일 이메일의 사용자가 이미 있으면 아무것도 하지 않는다(기존
비밀번호 보존). `aisast init-db` CLI 에서도 동일 로직을 재사용한다.

---

## 14. 데이터베이스 스키마

`aisast/db/models.py` (SQLAlchemy 2.0 Declarative):

| 테이블 | 주요 컬럼 | 관계 |
|--------|----------|------|
| `users` | `id`, `email`(unique), `hashed_password`, `role`, `is_active` | — |
| `projects` | `id`, `name`(unique), `description`, `repo_url`, `default_language`, `owner_id` | 1:N `scans` |
| `scans` | `id`(12자 hex), `project_id`, `source_path`, `status`, `error`, `started_at`, `finished_at`, `engine_stats`(JSON), `mois_coverage`(JSON) | 1:N `findings` |
| `findings` | `id`, `scan_id`, `finding_hash`, `rule_id`, `engine`, `message`, `severity`, `file_path`, `start_line`, `end_line`, `cwe_ids`(JSON), `mois_id`, `category`, `language`, `snippet`, `raw`(JSON) | 1:1 `triage` |
| `triage_records` | `id`, `finding_id`(unique), `verdict`, `fp_probability`, `rationale`, `recommended_fix`, `patched_code`, `model` | — |

스키마는 `startup` 이벤트에서 `Base.metadata.create_all()` 로 자동 생성된다. 운영
배포 시에는 Alembic 마이그레이션으로 전환하는 것을 권장한다.

---

## 15. 테스트

```bash
. .venv/bin/activate
pytest -q
```

현재 22개 테스트 / 기준 통과:

| 파일 | 커버리지 |
|------|----------|
| `tests/test_mois_catalog.py` | 49개 항목 수, 카테고리 분포, CWE 역조회, ID 유일성 |
| `tests/test_sarif_parser.py` | SARIF 파싱, MOIS 매핑, 엔진 우선순위 병합, SARIF 직렬화 라운드트립 |
| `tests/test_engine_registry.py` | 엔진 레지스트리, 가용성 점검, 바이너리 없음 환경에서 파이프라인 정상 종료 |
| `tests/test_llm_triage.py` | Noop 기반 Triager 결과 부착, JSON 추출기 관용성 |
| `tests/test_reports.py` | SARIF/HTML/Excel 생성(한글 섹션·XLSX 시그니처 확인) |
| `tests/test_bootstrap_admin.py` | 관리자 시드 1회 생성 보장, 기존 계정 미덮어쓰기 |
| `tests/test_scan_upload.py` | ZIP 안전 압축 해제, zip-slip 거부, Git URL 스킴 검증 |

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
aiSAST는 **bcrypt 를 직접 사용**하므로 passlib 가 설치되어 있어도 영향이 없다.
구버전에서 업그레이드했다면 `pip uninstall passlib` 후 `pip install -e '.[dev]'`
재실행을 권장한다.

### Docker 빌드에서 `openjdk-17-jre-headless` 실패
Debian trixie 이미지는 JDK 17을 제공하지 않는다. Dockerfile은 `openjdk-21-jre-headless` 를 사용한다. 수정한 경우 `docker compose build --no-cache api`.

### 로그인 422 Unprocessable Entity / "이메일 또는 비밀번호를 확인하세요"
증상: 프론트엔드에서 올바른 계정으로 로그인해도 실패. API 로그에
`POST /api/auth/login HTTP/1.1 422 Unprocessable Entity` 가 찍힘.

원인: Pydantic `EmailStr` 이 내부적으로 `email-validator` 라이브러리를 호출하는데,
이 라이브러리는 IANA special-use TLD 인 `.local` 을 "special-use or reserved
name" 으로 거부한다. `admin@aisast.local` 같은 기본 부트스트랩 계정 이메일이
422 로 차단되는 이유다.

해결: `aisast/api/schemas.py` 는 `EmailStr` 대신 느슨한 정규식 검증
(`^[^@\s]+@[^@\s]+\.[^@\s]+$`) 을 사용한다. `LoginRequest`·`UserCreate`·`UserOut`
가 모두 일반 `str` 타입 + `field_validator` 조합으로 정의돼 있으며, 입력값은
소문자로 정규화된다. `.local`·`.internal`·사내 도메인 모두 허용된다.

직접 검증:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@aisast.local","password":"aisast-admin"}'
# → {"access_token":"eyJ...","token_type":"bearer","role":"admin"}
```

### Vite 가 "ready" 로그까지 찍고도 브라우저 응답이 없음 (D-state hang)
증상: `docker compose logs frontend` 에 `VITE v5.x ready in Xms` 가 뜨는데
`curl http://127.0.0.1:5173/` 은 타임아웃, 컨테이너 내부에서 `wget` 도 타임아웃.
`docker compose exec frontend top` 으로 보면 node 프로세스가 **`D` 상태**에
수 GB VSZ 를 차지하고 있다. `netstat -ltn` 의 5173 라인에서 `Recv-Q` 가 0 이
아닌 값(예: 46)이면 확정.

원인: 호스트 `./frontend` 바인드 마운트 + chokidar 폴링 + macOS osxfs 가 파일
스캔으로 I/O 를 포화시켜 Vite 이벤트 루프가 디스크 대기 상태에 묶인다.

해결: 현재 `docker-compose.yml` 에는 바인드 마운트와 `CHOKIDAR_USEPOLLING` 이
모두 제거되어 있고, `vite.config.ts` 에서 `watch.usePolling=false` + node_modules/
dist/.vite 를 워치 대상에서 빼도록 설정되어 있다. 만약 구 설정이 잔존한다면:

```bash
docker compose kill frontend
docker compose rm -f frontend
docker volume rm aisast_aisast-node-modules 2>/dev/null
docker compose up -d --build --force-recreate --no-deps frontend
curl -sS http://127.0.0.1:5173/ -o /dev/null -w "HTTP %{http_code}\n"
```

결과가 `HTTP 200` 이면 정상. 이 모드에서는 HMR 이 없으므로 소스 수정 후에는
반드시 `docker compose build frontend && docker compose up -d frontend` 로
이미지를 리빌드해야 한다.

### `http://localhost:5173` 가 컨테이너에선 떠 있는데 브라우저에서만 안 열림
Vite 로그에 `VITE v5.x ready … Local: http://localhost:5173/` 까지 떴는데도
호스트 브라우저에서 접속이 안 된다면 원인은 대개 둘 중 하나다.

1. **macOS `localhost` IPv6 vs IPv4**: macOS에서는 `localhost` 가 먼저 `::1` 로
   해석되는데 Docker Desktop의 포트 퍼블리시는 IPv4(`0.0.0.0`)에만 적용된다.
   브라우저 주소창에 `http://127.0.0.1:5173/` 를 넣으면 바로 뜬다.
   Compose에는 `ports: "0.0.0.0:5173:5173"` 로 IPv4 바인딩을 명시해 두었다.
2. **API 프록시 타겟**: Vite의 `/api` 프록시는 *Vite 프로세스*가 호출하므로
   컨테이너 내부에서는 `http://localhost:8000` 이 아니라 `http://api:8000` 으로
   가야 한다. `VITE_API_TARGET` 환경변수로 주입되며, `vite.config.ts` 는
   해당 값이 없으면 로컬 `http://localhost:8000` 을 사용한다.

점검 명령:

```bash
# 호스트에서 IPv4로 직접
curl -v http://127.0.0.1:5173/

# 컨테이너 내부에서 자기 자신
docker compose exec frontend wget -qO- http://127.0.0.1:5173 | head

# 포트 퍼블리시 확인 — "0.0.0.0:5173->5173/tcp" 가 보여야 함
docker compose ps frontend
```

### 프론트엔드(http://localhost:5173)가 응답하지 않음
이전 버전 Compose는 `node:20-alpine` 이미지를 그대로 띄우고 바인드 마운트된
호스트 `frontend/` 안에서 `npm install` 을 매 기동 시 실행했다. macOS Docker
Desktop의 osxfs 바인드 마운트가 느려 `npm install` 이 수 분 간 멈춘 것처럼
보이고 로그도 버퍼링되어 출력되지 않는 문제가 있었다.

현재는 **전용 `frontend/Dockerfile`** 이 `node_modules` 를 빌드 타임에 설치하고,
Compose는 `node_modules` 를 named volume(`aisast-node-modules`)으로 올려
호스트 바인드와 충돌을 차단한다. Vite dev 서버는
`--host 0.0.0.0 --port 5173 --strictPort` 로 기동되고 `CHOKIDAR_USEPOLLING=true`
환경변수로 macOS 파일 변경 감지를 안정화한다.

디버깅 절차:

```bash
# 1) 컨테이너 상태
docker compose ps frontend

# 2) 실시간 로그 — "VITE v5.x  ready in Xms" 메시지가 보여야 정상
docker compose logs -f frontend

# 3) 내부에서 Vite 응답 확인
docker compose exec frontend wget -qO- http://127.0.0.1:5173 | head

# 4) node_modules 볼륨이 오염됐을 때 깨끗이 재생성
docker compose down
docker volume rm aisast_aisast-node-modules
docker compose up --build frontend

# 5) 5173 포트가 다른 프로세스에 점유된 경우(strictPort 로 즉시 실패)
lsof -i :5173
```

`package.json` 에 새 의존성을 추가했다면 **반드시** 이미지를 리빌드하세요:

```bash
docker compose build frontend
docker compose up -d frontend
```

### 로그인 403 / 401
부트스트랩 관리자가 생성되었는지 확인: API 로그에 `bootstrap admin created: …`
경고 메시지가 있어야 한다. 존재하지 않으면 `aisast init-db` 를 실행하거나
`docker compose exec api aisast init-db` 를 사용.

---

## 17. 변경 이력

> 기능이 수정/추가/제거될 때마다 본 섹션과 위 상세 섹션을 **동시에** 갱신한다.

### 2026-04-15 (오후 — 소스 입력 UX)
- **스캔 소스 입력 3-모드**: 기존 서버 경로 단일 입력은 Docker 환경에서 "내 PC의 경로를 왜 못 넣지?" 혼란을 유발했다. 이제 다음 3개 엔드포인트가 공존:
  - `POST /api/scans` — 서버 경로 (기존)
  - `POST /api/scans/upload` — 멀티파트 `.zip` 업로드, 500 MiB 상한, zip-slip 방지 압축 해제, 풀린 경로를 `source_path` 로 사용
  - `POST /api/scans/git` — `git clone --depth 1` 후 스캔, 완료 시 체크아웃 자동 정리. URL 스킴 검증(`http`/`https`/`ssh`/`git@`).
- **공유 볼륨**: `aisast-work` named volume 신설. api·worker 가 `/var/aisast-work` 로 동일 마운트. `AISAST_WORK_DIR=/var/aisast-work` 환경변수 주입.
- **Celery 태스크**: `clone_and_scan_task` 추가. 실패/크래시 시 `shutil.rmtree` 로 디렉터리 정리 후 `repo.mark_scan_failed`.
- **Pydantic 스키마**: `GitScanCreate` 신설 (URL 스킴 화이트리스트). `ScanCreate` 는 그대로.
- **프론트엔드**: `Projects.tsx` 전면 개편 — 서버 경로 / ZIP 업로드 / Git URL 3-탭, 파일 picker, 언어 힌트·2차 Pass·Triage 토글, 에러 표시, 재사용 가능한 `Tab` 컴포넌트. HTML 리포트 다운로드 링크도 노출.
- **테스트**: `test_scan_upload.py` 추가 (정상 압축 해제, zip-slip 거부, Git URL 검증) → 총 22 passing.
- **검증(end-to-end)**: `curl /api/scans/upload` 로 Python 샘플 zip 업로드 → Opengrep+Bandit 합쳐 5 findings 탐지 (`mois-sr1-4-python-shell-true` 포함). `/api/scans/git` 으로 `OWASP/NodeGoat.git` clone 태스크 수신/실행 확인.
- **§5, §12, §15, §16 업데이트**.

### 2026-04-15
- **Frontend Docker 분리**: 전용 `frontend/Dockerfile` (node:20-alpine, 빌드 타임 `npm install`) 추가. `docker-compose.yml` 프론트엔드 서비스가 `build:` 를 사용하도록 전환.
- **Vite 기동 플래그**: `--host 0.0.0.0 --port 5173 --strictPort` 고정. `vite.config.ts` 에 `server.host='0.0.0.0'`, `strictPort`, `hmr.clientPort=5173` 추가.
- **API 프록시 타겟**: `VITE_API_TARGET` 환경변수로 주입(로컬=기본 `http://localhost:8000`, Docker=`http://api:8000`).
- **포트 바인딩**: `ports: "0.0.0.0:5173:5173"` 로 IPv4 고정(IPv6 `::1` 해석 이슈 방지).
- **FindingsTable**: `React.Fragment` + `key` 사용으로 교체(무키 프래그먼트 경고 제거).
- **Vite D-state hang 수정 (중요)**: 호스트 `./frontend` 바인드 마운트 + `CHOKIDAR_USEPOLLING=true` + macOS osxfs 조합이 Vite 노드 프로세스를 **D-state(uninterruptible I/O wait)** 로 묶어 TCP 연결은 수락하지만 HTTP 응답이 멈추는 현상이 확인됨 (`Recv-Q=46`, `%VSZ=603%`). 해결:
  - `docker-compose.yml` 프론트엔드 서비스에서 `volumes:` (바인드 마운트 + `aisast-node-modules`) **제거**. 이미지에 구운 소스를 그대로 사용 (HMR 없음).
  - `CHOKIDAR_USEPOLLING` 환경변수 삭제.
  - `vite.config.ts` 의 `server.watch.usePolling=false` + `ignored: ['**/node_modules/**','**/dist/**','**/.vite/**']` 로 워치 범위 축소.
  - `healthcheck` 제거 (실패한 헬스체크가 정체된 wget 프로세스를 계속 쌓아 상황 악화).
  - 소스 수정 후에는 `docker compose build frontend && docker compose up -d frontend` 로 재빌드.
- **검증**: `curl http://127.0.0.1:5173/` → HTTP 200, 570 bytes, 71ms. `http://localhost:5173/` 및 `http://127.0.0.1:5173/` 양쪽 정상 응답 확인.
- **트러블슈팅 §16**: "Vite가 ready 로그까지 찍고도 브라우저 응답이 없음 (D-state I/O wait)" 케이스 추가.
- **로그인 422 수정 (중요)**: Pydantic `EmailStr` → `email-validator` 가 `.local` TLD 를 special-use 로 거부하여 기본 부트스트랩 계정 `admin@aisast.local` 로 422 실패. `aisast/api/schemas.py` 의 `LoginRequest`·`UserCreate`·`UserOut` 을 일반 `str` + `field_validator` 기반 정규식 검증으로 교체하고 입력 이메일을 소문자 정규화. §13 인증 섹션과 §16 트러블슈팅에 반영. `curl http://127.0.0.1:8000/api/auth/login` / `curl http://127.0.0.1:5173/api/auth/login` 양쪽에서 HTTP 200 JWT 발급 확인.

### 2026-04-14
- **Init**: 초기 버전 0.1.0 릴리스 — 카탈로그(49), 엔진 어댑터(6), SARIF 파이프라인, LLM Triage(3 프로바이더), FastAPI+JWT+RBAC, Celery 워커, React UI, SARIF/HTML/Excel/PDF 리포트, Docker Compose 스택.
- **Docker**: Debian trixie 호환을 위해 `openjdk-17-jre-headless` → `openjdk-21-jre-headless` 로 변경.
- **Packaging**: `pyproject.toml` 의 `readme` 를 `README.md` 로 변경하고 Dockerfile `COPY` 단계에 포함.
- **Auth**: passlib 제거, **bcrypt 직접 사용**으로 전환. 72바이트 상한 안전 처리.
- **Bootstrap**: API `startup` 이벤트에서 `ensure_bootstrap_admin()` 자동 실행. 기본 계정 `admin@aisast.local / aisast-admin`. env: `AISAST_BOOTSTRAP_ADMIN_EMAIL/PASSWORD/DISPLAY_NAME`.
- **CLI**: `aisast init-db --seed-admin/--no-seed-admin` 옵션 추가.
- **Frontend**: 로그인 페이지에 부트스트랩 계정 안내 배지 추가, 기본 입력값 프리셋.
- **Tests**: 부트스트랩 시드/미덮어쓰기 검증 2건 추가 → 총 19 passing.
