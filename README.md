# OpenSAST

**오픈소스 기반 SW 보안약점 진단도구** — 행정안전부 「소프트웨어 보안약점 진단가이드(2021)」 구현단계 **49개 항목**을 커버하는 다중 엔진 SAST 오케스트레이터.

> **현재 버전**: v0.6.0 (2026-04-17 릴리스)
> **MOIS 커버리지**: 46/49 항목 (93%) — 나머지 3개(SR1-15/SR5-3/SR5-6)는 C/C++ 메모리 취약점으로 현재 지원 언어 범위 밖
> **라이선스**: Apache-2.0 (모든 의존 엔진 OSS 라이선스 사용)

## 구성 요소 (v0.6.0)

- **백엔드**: FastAPI, JWT+RBAC+멀티테넌시(Organization), Celery 비동기 오케스트레이션, Postgres(복합 인덱스 7종), Redis(캐시·큐·pub-sub)
- **분석 엔진**: Opengrep(Semgrep CE), Bandit, gosec, SpotBugs (+ CodeQL/ESLint 는 [ADR-0001 rev.2](docs/adr/ADR-0001-unified-analysis-pipeline.md) 결정에 따라 Phase 1 에서 **제거 예정**, Joern 이 심층 분석 엔진으로 대체 도입)
- **LLM Triage**: Ollama+Gemma(오프라인) / Anthropic Claude(온라인) / Noop — 원본 Finding **제거 금지** 원칙, tenacity 3회 재시도, Redis SHA-256 캐시 24h TTL
- **룰셋**: `rules/opengrep/{java,python,javascript,go,common}` (30개 YAML · 113개 룰), `rules/codeql/java` (12개 쿼리, Phase 1 에서 Joern `.sc` 로 재작성 예정)
- **리포트**: SARIF 2.1.0, HTML(Jinja2), Excel(openpyxl), PDF(WeasyPrint, 한글 폰트 내장)
- **프론트엔드**: React + TypeScript + Tailwind CSS + Vite
- **CLI**: `opensast scan|serve|list-mois|engines|report`

## 빠른 시작 (개발 환경)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# 1) 49개 항목 카탈로그 확인
opensast list-mois

# 2) 설치된 엔진 바이너리 확인
opensast engines

# 3) 디렉터리 스캔 (LLM 비활성, 1차 Pass만)
#    ⚠️ --no-second-pass 는 v0.7 에서 --mode fast 로 대체 예정 (ADR-0001)
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

운영 환경에서는 `OPENSAST_BOOTSTRAP_ADMIN_EMAIL`, `OPENSAST_BOOTSTRAP_ADMIN_PASSWORD` 환경변수로 반드시 변경한 뒤 기동하세요. 동일 이메일 계정이 이미 존재하면 부트스트랩 로직은 건너뜁니다.

## 📖 문서 지도

| 문서 | 용도 |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | 설치·설정·CLI·REST API·엔진·LLM·리포트·프론트엔드·DB 스키마