# OpenSAST

**오픈소스 기반 SW 보안약점 진단도구** — 행정안전부 「소프트웨어 보안약점 진단가이드(2021)」 구현단계 49개 항목을 커버하는 다중 엔진 SAST 오케스트레이터.

## 구성 요소

- **백엔드(FastAPI)**: 프로젝트·스캔·리포트 API, JWT+RBAC 인증, Celery 비동기 오케스트레이션
- **분석 엔진**: Opengrep(Semgrep CE), Bandit, ESLint, gosec, SpotBugs(+Find Security Bugs), CodeQL
- **LLM 후처리**: Ollama+Gemma(오프라인) / Anthropic Claude(온라인) / Noop(더미)
- **룰셋**: `rules/opengrep/{java,python,javascript,go,common}` 및 `rules/codeql/java`
- **리포트**: SARIF 2.1.0, HTML(Jinja2), Excel(openpyxl), PDF(WeasyPrint)
- **프론트엔드**: React + TypeScript + Tailwind CSS + Vite
- **CLI**: `opensast scan`, `opensast serve`, `opensast list-mois`, `opensast engines`, `opensast report`

## 빠른 시작 (개발 환경)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# 1) 49개 항목 카탈로그 확인
opensast list-mois

# 2) 설치된 엔진 바이너리 확인
opensast engines

# 3) 디렉터리 스캔 (LLM 비활성, 1차 Pass만)
opensast scan ./examples --no-second-pass --no-triage -o result.sarif

# 4) 리포트 변환
opensast report result.sarif --html report.html --excel report.xlsx
```

## Docker Compose 전체 스택

```bash
cp .env.example .env
docker compose up --build
```

서비스:
- API: http://localhost:8000 (`/docs` OpenAPI)
- 프론트엔드: http://localhost:8080
- Postgres: 5432, Redis: 6379, Ollama: 11434

**최초 로그인 계정** (API 최초 기동 시 자동 생성, role=`admin`):

| 이메일 | 비밀번호 |
|--------|----------|
| `admin@opensast.local` | `opensast-admin` |

운영 환경에서는 `OPENSAST_BOOTSTRAP_ADMIN_EMAIL`, `OPENSAST_BOOTSTRAP_ADMIN_PASSWORD`
환경변수로 반드시 변경한 뒤 기동하세요. 동일 이메일의 계정이 이미 존재하면
부트스트랩 로직은 건너뜁니다.

## 배포 프로파일

`OPENSAST_PROFILE` 이 보안·운영 기본값 번들을 고릅니다. **지정하지 않으면
`local` 로 동작해 CORS 가 `*`, API docs 노출, rate limit 비활성 상태가 됩니다.**

| 프로파일 | 용도 | 특징 |
|---|---|---|
| `local` | 개발자 워크스테이션 | 보안 기본값 완화, docs 노출, DEBUG 로그 |
| `docker` | 팀 / 온프레미스 | `docker-compose.yml` 이 자동 지정 |
| `cloud` | 프로덕션 | docs 비활성, JSON 로그, **약한 시크릿·빈 CORS 로는 기동 거부** |

프로덕션 기동:

```bash
OPENSAST_SECRET_KEY=$(openssl rand -hex 32) \
OPENSAST_CORS_ORIGINS=https://sast.corp.com \
OPENSAST_BOOTSTRAP_ADMIN_PASSWORD='<강력한 비밀번호>' \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

docker compose run --rm api alembic upgrade head   # 스키마는 별도 단계
```

## 2-Pass 분석 파이프라인

1. **1차 Pass** (`opensast.engines.registry.FIRST_PASS_ENGINES`): Opengrep/Bandit/ESLint/gosec
2. **2차 Pass**: CodeQL/SpotBugs
3. **3단계 LLM Triage**: `opensast.llm.triage.Triager` — 원본 Finding을 **제거하지 않고** 오탐 확률·판정 근거·조치 방안을 `triage` 필드에 기록 (행안부 지침 준수)

한 Pass 안의 엔진은 동시에 실행되며, 2차 Pass 가 생략되거나 triage 상한에 걸리면
그 사실이 `ScanResult.notes` 에 기록됩니다 — 조용히 축소되지 않습니다.

## 49개 항목 ↔ CWE ↔ 엔진 매핑

`opensast/mois/catalog.py` 에서 단일 소스로 관리되며, `opensast list-mois` 및 `/api/mois/items` 로 조회한다.

## 📖 문서

문서는 성격별로 나뉘어 있습니다 ([ADR-0007](docs/adr/0007-documentation-architecture.md)).

| 알고 싶은 것 | 문서 |
|---|---|
| **어떻게 쓰는가** | **[docs/guide/](docs/guide/README.md)** — 설치·설정·CLI·API·운영 |
| 지금 무엇이 있는가 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| 왜 그렇게 만들었는가 | [docs/adr/](docs/adr/README.md) |
| 무엇을 할 것인가 | [docs/ROADMAP.md](docs/ROADMAP.md) |
| 그때는 어땠는가 | [docs/reviews/](docs/reviews/) |

기여 방법은 [CONTRIBUTING.md](CONTRIBUTING.md), 취약점 신고는
[SECURITY.md](SECURITY.md) 를 참조하세요.

## 라이선스

Apache-2.0

> **참고**: CodeQL 엔진은 GitHub Advanced Security 약관의 적용을 받습니다.
> 상업적 사용 시 라이선스 조건을 확인하세요.
