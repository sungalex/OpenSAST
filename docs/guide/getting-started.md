# 설치와 첫 실행

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 프로젝트 개요

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

## 설치

### 2.0 지원 OS 매트릭스

| 등급 | OS | 실행 방법 | 상태 |
|------|-----|-----------|------|
| **Tier 1 — 완전 지원** | Linux x86_64 / arm64 (Ubuntu 22.04+, Debian 12+, RHEL 9+) | 로컬 pip 또는 Docker Compose | ✅ CI 정기 검증 |
| **Tier 1 — 완전 지원** | macOS (Apple Silicon / Intel) | Docker Compose 권장 | ✅ CI 정기 검증 |
| **Tier 2 — 권장 경로** | **Windows 10/11 + WSL2** | WSL 안에서 Docker Compose | ✅ CI smoke 검증, 상세 가이드: [docs/install-windows-wsl2.md](../install-windows-wsl2.md) |
| **Tier 3 — Best-effort** | macOS 네이티브 pip 설치 | `brew install pango cairo` 후 `pip install -e '.[dev]'` | 엔진 바이너리는 별도 수동 설치 필요 |

> **엔진 바이너리는 OpenSAST 에 번들되지 않는다.** 설치돼 있지 않은 엔진은 건너뛰므로 스캔은 성공하지만 해당 언어의 결과가 비게 된다. 현재 상태는 `opensast engines` 로 확인하고, 설치 명령은 [`pipeline-and-engines.md` §7.1](pipeline-and-engines.md#71-엔진-설치) 에 있다.
| **Unsupported** | Windows 네이티브 | — | Semgrep/WeasyPrint/Celery prefork 호환성 문제로 **지원하지 않음**. WSL2 사용 권장 |
| **Unsupported** | FreeBSD/OpenBSD | — | 공식 엔진 바이너리 없음 |

> **결론**: macOS·Linux 는 네이티브/Docker 양쪽 지원, Windows 는 **WSL2 + Docker
> Desktop** 을 통해서만 지원합니다. 상세 설치 가이드는
> [install-windows-wsl2.md](../install-windows-wsl2.md) 참조.

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
