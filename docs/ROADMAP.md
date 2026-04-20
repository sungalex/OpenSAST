# aiSAST 고도화 전략 및 로드맵 (v0.4.1 → v1.0)

> **문서 기준일**: 2026-04-16 (v0.6.0 룰 확대 반영: 2026-04-17)
> **분석 대상 버전**: v0.6.0 (v0.5.0 관측성/성능 + v0.6.0 룰 커버리지 확대)
> **문서 목적**: 현 코드베이스의 구현 완성도를 계층별로 진단하고, v1.0 (KISA CC 인증 트랙) 까지의 단계별 고도화 경로를 제시한다.

---

## 목차

1. [한 줄 요약](#1-한-줄-요약)
2. [현황 진단](#2-현황-진단)
3. [계층별 Gap 매트릭스](#3-계층별-gap-매트릭스)
4. [버전별 로드맵](#4-버전별-로드맵)
   - [v0.4.2 — 버그 픽스 & Quick Wins](#v042--버그-픽스--quick-wins-1주)
   - [v0.5.0 — 관측성 · 성능 · 확장성 기반](#v050--관측성--성능--확장성-기반-3~4주)
   - [v0.6.0 — 룰 커버리지 확대 & 멀티테넌시](#v060--룰-커버리지-확대--멀티테넌시-4~6주)
   - [v0.7.0 — 생태계 통합](#v070--생태계-통합-4~6주)
   - [v1.0.0 — KISA CC 인증 준비](#v100--kisa-cc-인증-준비-2~3개월)
5. [이번 주 Quick Wins (PR 단위)](#5-이번-주-quick-wins-pr-단위)
6. [핵심 리스크 & 완화 전략](#6-핵심-리스크--완화-전략)
7. [부록 — 검증 노트 (Spot Check 결과)](#7-부록--검증-노트-spot-check-결과)

---

## 1. 한 줄 요약

> **"뼈대 · 파이프라인 · 문서화는 이미 인상적이지만, 버그픽스 1주 → 관측성/성능 4주 → 룰커버리지/멀티테넌시 6주 순서로 가면 v1.0 KISA CC 트랙에 안정적으로 올라설 수 있다."**

aiSAST는 2-Pass 파이프라인 · 6개 엔진 통합 · MOIS 49 카탈로그 · LLM Triage 원본 보존 원칙 · 플러그인 레지스트리 · 3-프로파일 설정 등 **구조적 완성도는 매우 높다**. 반면, 실제 사용 가치를 결정짓는 **(1) YAML 룰 커버리지**, **(2) 엔터프라이즈 운영 기반**(멀티테넌시/관측성/시크릿/컨테이너 보안), **(3) 몇몇 파이프라인 결함**(severity 비교 버그, 2nd pass 자동 비활성 조건, 하드코딩 상수)이 남아있다.

---

## 2. 현황 진단

### 2.1 잘 된 부분 (v1.0급 완성도)

| 영역 | 위치 | 평가 |
|---|---|---|
| 2-Pass 파이프라인 | `aisast/orchestrator/pipeline.py` | `FIRST_PASS_ENGINES` / `SECOND_PASS_ENGINES` 분리 구조 명확, LLM triage 통합까지 단일 진입점 |
| MOIS 49 카탈로그 | `aisast/mois/catalog.py` | 49개 항목 전부 등록, CI에서 `assert len(MOIS_ITEMS) == 49` 강제 |
| LLM Triage 원칙 | `aisast/llm/triage.py:31-34` | **원본 Finding 절대 제거 금지** 원칙 주석+코드로 강제, Ollama/Anthropic/Noop 3개 프로바이더 |
| 플러그인 레지스트리 | `aisast/plugins/registry.py` | `Registry[T]` 제네릭, entry_points 자동 발견, `OPENSAST_PLUGINS_DISABLED` 화이트리스트 |
| 3-프로파일 설정 | `aisast/config.py` | `local/docker/cloud` 자동 기본값 + `validate_profile()` 배포 전 경고 |
| RBAC + 계정 잠금 + 비번정책 | `aisast/api/security.py` | bcrypt NFC 정규화, 4종 문자 클래스 검증, 공통 암호 블랙리스트, 계정 잠금 |
| 리포트 4종 생성기 | `aisast/reports/` | SARIF / HTML / PDF / Excel 모두 구현, 한글 폰트 지원 |
| OS 매트릭스 CI | `.github/workflows/ci.yml` | Ubuntu/macOS/Windows × amd64/arm64 · Self-SAST 회귀 포함 |
| 설계 문서 | `docs/ARCHITECTURE.md`, `docs/USER_GUIDE.md` | 각각 500+ / 1500+ 라인 수준으로 상세 |

### 2.2 해결해야 할 핵심 약점

| 영역 | 문제 요지 | 영향 |
|---|---|---|
| **룰 커버리지** | MOIS 49 중 **13개만 매핑** = 26.5% | 실사용 시 탐지 공백. SAST 도구의 본질적 가치 직결 |
| **엔터프라이즈 운영 기반 부재** | 관측성(메트릭/트레이싱) · 멀티테넌시 · 시크릿 관리 · 컨테이너 보안 0 | 프로덕션 운영 불가, KISA CC 트랙 블로커 |
| **파이프라인 세부 결함** | severity 문자열 비교 버그, 2nd pass 자동 비활성 조건, 하드코딩 50/3600 | 정확도 저하 + 사용자 혼란 |
| **엔진/워커 통합 테스트 전무** | 모든 엔진이 `MagicMock` 뒤, Celery도 `MagicMock` | 회귀 위험, 실제 동작 검증 불가 |
| **계획서 약속 미이행** | VS Code 확장 · GitLab CI · Jenkins 플러그인 · PR 통합 UI | 생태계 채택 제약 |

---

## 3. 계층별 Gap 매트릭스

심각도 기준: 🔴 Critical (즉시) · 🟠 High (v0.5 이내) · 🟡 Medium (v0.6~0.7) · 🟢 Low (v1.0)

### 3.1 Rules & 엔진 탐지 정확도

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| R1 | `rules/opengrep/**` | ~~MOIS 49 중 13개만 커버~~ → **v0.6.0에서 46/49 (93%) 달성**. Opengrep 30개 YAML(113개 룰) + CodeQL 12개 쿼리. 미커버 3개(SR1-15, SR5-3, SR5-6)는 C/C++ 메모리 취약점으로 현재 지원 언어 범위 밖 | ✅ |
| R2 | `rules/codeql/java/` | ~~`toctou.ql` 1개 파일뿐~~ → **v0.6.0에서 12개 쿼리** (SQL injection taint, XXE, SSRF, integer overflow, deserialization, unbounded loop, null-deref, resource-leak, race-condition, unchecked-return, uninitialized-variable + 기존 toctou) | ✅ |
| R3 | `aisast/sarif/merge.py:56` | `candidate.severity.value < existing.severity.value` 문자열 비교 → `"LOW" < "MEDIUM"` 가 `True` 라 **LOW 가 MEDIUM 을 이김** (HIGH < LOW 는 우연히 맞음) | 🔴 |
| R4 | `aisast/sarif/merge.py:27-36` | 중복 제거 키가 `(file, line, cwe_tuple)` — snippet/message 차이 무시, 의미론적 중복 미탐지 | 🟡 |
| R5 | `aisast/sarif/parser.py:156-172` | SARIF logicalLocation, relocation, threadFlows, taxa 등 고급 필드 미처리 | 🟡 |
| R6 | `aisast/sarif/parser.py:88-110` | SARIF version 검증 없음, 1.x 호환성 정의 없음 | 🟢 |
| R7 | `rules/opengrep/java/sql-injection.yml` 전반 | 룰별 `metadata.remediation` 필드 없음 (조치 권고가 룰에 내장되지 않음) | 🟠 |

### 3.2 Orchestrator / Pipeline

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| O1 | `aisast/orchestrator/pipeline.py:66` | `enable_second_pass and not options.engines` — 사용자가 엔진 목록을 지정하면 2nd pass 가 **조용히 전체 비활성**됨. 직관에 반함 | 🟠 |
| O2 | `aisast/orchestrator/pipeline.py:97-126` | `_run_pass` 루프에 **진행률 콜백/훅 없음** → 프론트 실시간 표시 불가 | 🟠 |
| O3 | `aisast/orchestrator/pipeline.py:74-78` | Triage 실패 시 `needs_review` 자동 설정은 하지만 실패 원인 구조화 로깅 부족 | 🟡 |
| O4 | `aisast/orchestrator/tasks.py:25-57` | `@celery_app.task()` 에 `retry` / `max_retries` / `acks_late` / `autoretry_for` 전혀 없음 | 🟠 |
| O5 | `aisast/orchestrator/tasks.py` | Celery `revoke/terminate` 경로 없음 → **스캔 취소 불가** | 🟠 |
| O6 | `aisast/orchestrator/celery_app.py:61` | `task_time_limit=3600` 하드코딩 — 대형 프로젝트 CodeQL 빌드 시 초과 가능 | 🟡 |
| O7 | `aisast/orchestrator/tasks.py:60-112` | `clone_and_scan_task` 에서 임시 디렉터리 삭제 타이밍이 스캔 완료 이후 — 대용량 저장소 시 디스크 폭주 위험 | 🟡 |
| O8 | `aisast/engines/base.py:50-54` | `BinaryNotFound` 만 처리, `TimeoutExpired` / `ResourceError` / `DiskFull` 미처리 | 🟠 |
| O9 | `aisast/engines/codeql.py:64-72` | `database create` 실패 시 stderr 로그 없음, analyze 전 DB 상태 검증 없음 | 🟠 |

### 3.3 LLM Triage

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| L1 | `aisast/llm/triage.py:45-75` | findings **순차 처리** — 1000개 × 2초 = 30분 직렬. 배치/병렬 없음 | 🟠 |
| L2 | `aisast/llm/triage.py:71,111,116,120` | `fp_probability=50` 4곳 하드코딩 — 설정 불가 | 🟡 |
| L3 | `aisast/llm/triage.py` | **결과 캐싱 없음** — 동일 rule/파일/라인/snippet 재분석 시 LLM 재호출 | 🟠 |
| L4 | `aisast/llm/ollama.py:L29`, `anthropic.py:L40` | 재시도 / 서킷브레이커 / 토큰 레이트 리밋 없음 | 🟠 |
| L5 | `aisast/llm/triage.py:152-154` | `factory()` 호출이 `TypeError` 포괄 — 초기화 실패 원인 감춰짐 | 🟡 |
| L6 | `aisast/llm/prompts.py` | Few-shot 예시 없음 (system prompt + user template 만) | 🟡 |

### 3.4 Database & 서비스 레이어

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| D1 | `aisast/db/models.py` 전반 | **복합 인덱스 0개**. Finding(scan_id, severity, status), Scan(project_id, status, created_at), SuppressionRule(project_id, kind), AuditLog(user_id, created_at) 등 핵심 쿼리 풀스캔 | 🟠 |
| D2 | `aisast/db/models.py` | `organization_id` FK 없음 → **싱글테넌시**, 조직 격리 불가 | 🟠 |
| D3 | `aisast/db/models.py:100-107` | Finding.status 전이 규칙이 **주석**으로만 존재, DB 제약(enum) 없음 | 🟡 |
| D4 | `aisast/db/migrate.py:31-56` | `auto_migrate` 가 컬럼 **추가만** 지원 (drop/rename 불가), `alembic/versions/` 에 초기 마이그레이션 1개 | 🟠 |
| D5 | `aisast/services/base.py:65-85` | `session.commit()` 을 서비스에서 직접 호출 — 라우트 응답 후 예외 시 부분 커밋 위험. 트랜잭션 경계 불명확 | 🟡 |
| D6 | `aisast/services/finding_service.py:82-88`, `gate_service.py:115-147` | `path_glob` / text LIKE 필터가 DB 아닌 메모리에서 처리, N+1 위험 | 🟠 |
| D7 | `aisast/services/finding_service.py:46-100` | `search()` 가 offset-based 페이지네이션만 — 대규모 결과셋 느림 | 🟡 |

### 3.5 API / 인증 / 미들웨어

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| A1 | `aisast/api/security.py:36-42` | JWT payload 에 `iat` / `jti` / `aud` / `iss` 없음 | 🟠 |
| A2 | `aisast/api/security.py` | **Refresh token 없음**, 블랙리스트 없음 — 로그아웃 즉시 무효화 불가 | 🟠 |
| A3 | `aisast/api/deps.py:26-38` | 매 요청마다 DB 조회로 user 확인 — 권한 변경 즉시 반영되지만 성능 저하. Redis 캐시 필요 | 🟡 |
| A4 | `aisast/api/routes/auth.py:44,81` | 로그인 실패 시 타이밍 공격 완화 없음 (응답 시간 차이로 계정 존재 유추 가능) | 🟡 |
| A5 | `aisast/api/middleware/rate_limit.py` | slowapi **in-memory** → 다중 인스턴스 배포 시 우회 | 🟠 |
| A6 | `aisast/api/middleware/security_headers.py:36-46` | CSP `unsafe-inline` 허용 → XSS 위험, nonce/hash 미적용 | 🟠 |
| A7 | `aisast/api/` 전체 | **CSRF 토큰 전무** — SPA POST/PUT 취약 | 🟠 |
| A8 | `aisast/api/middleware/__init__.py:29-36` | CORS `allow_methods="*"`, `allow_headers="*"` 와일드카드 | 🟡 |
| A9 | `aisast/config.py:122-124` | bootstrap admin 자격증명 env 평문, 시크릿 매니저(Vault/AWS SM) 미연동 | 🟠 |
| A10 | `aisast/api/routes/findings.py:113-149` | `/ask` (NL 검색) LLM 에러 로깅 미흡, fallback 동작 불투명 | 🟡 |

### 3.6 컨테이너 / 배포 / 운영

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| C1 | `Dockerfile` | **root 실행**, `USER` 지시문 없음 | 🔴 |
| C2 | `Dockerfile` | `HEALTHCHECK` 지시문 없음 | 🟠 |
| C3 | `Dockerfile` | single-stage — builder 분리 없음, 이미지 ~1GB (openjdk+cairo+build-essential 포함) | 🟡 |
| C4 | `docker-compose.prod.yml` | TLS 기본 비활성 (443 주석 처리), secret **파일 마운트** 없음 (env 평문) | 🟠 |
| C5 | `docker-compose.yml` | minio 기본 자격증명 `minioadmin/minioadmin` | 🟠 |
| C6 | `deploy/nginx/nginx.conf:L77` | HSTS 헤더 주석 처리, rate limit 규칙 없음 | 🟠 |
| C7 | 전체 | **Prometheus `/metrics` 없음** | 🟠 |
| C8 | 전체 | **OpenTelemetry 통합 없음** (트레이싱/메트릭/로그 signal 전부 0) | 🟠 |
| C9 | `aisast/utils/logging.py` | JSON 구조화 로깅 옵션 없음 (Rich 콘솔 전용) | 🟡 |
| C10 | `aisast/api/app.py:67-83` | `/health`/`/ready` 가 정적 응답 — DB/Redis/Celery broker ping 미포함 | 🟡 |

### 3.7 테스트 / CI / 의존성

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| T1 | `tests/conftest.py:73-81` | Celery tasks `MagicMock` 처리 — **워커 통합 테스트 없음** | 🟠 |
| T2 | `tests/test_engine_registry.py` | 엔진 등록 여부만 검증, **실제 실행 통합 테스트 없음** | 🟠 |
| T3 | `tests/fixtures/` | SARIF 샘플 파일 `opengrep-sample.sarif.json` 1개만 | 🟡 |
| T4 | `tests/test_llm_triage.py` | `NoopLLMClient` 더미만 검증 — 실제 프롬프트/응답 파싱 미검증 | 🟡 |
| T5 | `frontend/src/**/*.test.tsx` | Vitest 단위 테스트만 (8개 파일), **Playwright E2E 없음** | 🟡 |
| T6 | 전체 | 성능/부하 테스트 없음 (대용량 SARIF, 수만 Finding 조회 시나리오) | 🟡 |
| T7 | 전체 | 침투 테스트 / SQLi / XSS / CSRF 시나리오 없음 | 🟡 |
| T8 | `.github/workflows/ci.yml:L91` | `pytest-cov>=5.0` 의존성은 설치되는데 `--cov` 플래그 미사용 → **커버리지 리포트 0** | 🟠 |
| T9 | `.github/workflows/ci.yml` | mypy 미실행 (`pyproject.toml` 에 `mypy>=1.10` 있음), `pip-audit` 없음 | 🟠 |
| T10 | `.github/` | `dependabot.yml` 없음, renovate 없음 | 🟠 |
| T11 | `pyproject.toml` | **lockfile 없음** — 의존성 재현성 불안정 | 🟠 |
| T12 | 전체 | SBOM 생성 없음 (CycloneDX/SPDX), 컨테이너 이미지 서명(cosign) 없음 | 🟡 |

### 3.8 프론트엔드 / CLI / 생태계

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| F1 | `frontend/src/App.tsx` | **ErrorBoundary 없음**, 글로벌 에러 핸들링 없음 | 🟠 |
| F2 | `frontend/src/pages/*.tsx` | 페이지마다 `[loading, error, busy]` state 중복, **React Query/SWR 없음** | 🟡 |
| F3 | `frontend/src/pages/ScanDetail.tsx` | 스캔 상태 **polling/WebSocket 없음** (정적 표시만) | 🟠 |
| F4 | `frontend/src/pages/ScanDetail.tsx:140-151` | diff 탭이 단순 목록만, **side-by-side 뷰어 없음** | 🟡 |
| F5 | `frontend/src/components/FindingsTable.tsx:170-176` | snippet `<pre>` plain text, syntax highlight / 라인 넘버링 없음 | 🟡 |
| F6 | `frontend/tailwind.config.js:2-14` | `dark:` 지원 없음 | 🟢 |
| F7 | 전체 | `aria-label` / `role` / 키보드 내비게이션 없음 (a11y 0) | 🟡 |
| F8 | 전체 | i18n 라이브러리 없음, 한글 고정값 — `name_en` 필드 활용 불가 | 🟡 |
| F9 | `frontend/src/pages/MoisCatalog.tsx` | 단순 테이블, 검색/상세 없음 | 🟢 |
| F10 | 프로젝트 루트 | **VS Code 확장 없음** (계획서 약속) | 🟡 |
| F11 | 프로젝트 루트 | **GitLab CI 템플릿 / Jenkins 플러그인 없음** (계획서 약속) | 🟡 |
| F12 | `aisast/cli.py` | 로컬 스캔이 `run_scan` 직접 호출 — Celery 우회, 대용량 시 메모리 오버헤드 | 🟡 |

### 3.9 리포트 / MOIS 카탈로그

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| P1 | `aisast/reports/pdf.py:19-22` | WeasyPrint import 실패 시 HTML 원본 반환 — PDF 생성 실패 **은폐** | 🟡 |
| P2 | `aisast/reports/pdf.py` | MOIS 공식 보고서 **CSS 템플릿 없음** (표지/목차/요약/상세/조치권고) | 🟠 |
| P3 | `aisast/reports/excel.py:94-105` | 3시트 구성은 되어 있으나 openpyxl **차트 미사용**, pivot 없음 | 🟢 |
| P4 | `aisast/mois/references.py:329-380` | 내장 CWE→OWASP/SANS/PCI 매핑은 하드코딩, 사용자 오버레이는 로드만 되고 통합 미흡 | 🟡 |
| P5 | `aisast/mois/loader.py:36-60` | YAML 오버레이 병합 시 dict 순서 의존 — 결과 재현성 불안정 | 🟡 |
| P6 | `aisast/plugins/registry.py` | `report_registry` 정의되나 `aisast/reports/__init__.py` 는 **하드코드된 `build_sarif`/`build_html`** 직접 호출 — 플러그인 확장 경로 미활용 | 🟡 |

### 3.10 문서화

| # | Gap | 심각도 |
|---|---|---|
| DOC1 | `CONTRIBUTING.md` 없음 (기여 가이드, 플러그인/룰 작성 HOW-TO) | 🟡 |
| DOC2 | `SECURITY.md` 없음 (CVE 신고 SLA, 보안 정책) | 🟡 |
| DOC3 | `docs/API-REFERENCE.md` 없음 (`/docs` OpenAPI 자동 생성만) | 🟡 |
| DOC4 | 운영 매뉴얼 없음 (DB 마이그레이션, 시크릿 로테이션, 장애 대응) | 🟡 |
| DOC5 | 플러그인 개발 가이드 없음 (entry_points, Registry API) | 🟡 |

---

## 4. 버전별 로드맵

### v0.4.2 — 버그 픽스 & Quick Wins (1주)

> **목표**: 고장난 것부터 고치고, 낮은 노력으로 큰 효과를 내는 항목부터.

#### 범위
1. **`sarif/merge.py:56` severity 비교 수정**
   - 현재: `candidate.severity.value < existing.severity.value` (문자열) → `"LOW" < "MEDIUM"` 이 `True`
   - 수정: `_SEVERITY_RANK = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}` 기반 숫자 비교
   - 회귀 테스트 추가 (HIGH vs MEDIUM, MEDIUM vs LOW, HIGH vs LOW, 동일 severity)
2. **`orchestrator/pipeline.py:66` 2nd pass 조건 재설계**
   - 현재: `enable_second_pass and not options.engines` — 엔진 지정 시 2nd pass 전체 무시
   - 수정: 엔진 지정 시 해당 목록 내 `SECOND_PASS_ENGINES` 교집합을 실행
3. **`llm/triage.py` 하드코딩 제거**
   - `fp_probability=50` 4곳 → `settings.llm_default_fp_probability` (기본 50)
4. **`Dockerfile` 하드닝**
   - multi-stage (`builder` + `runtime`)
   - `RUN useradd -m -u 10001 aisast && USER aisast`
   - `HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1`
5. **CI 커버리지 + 품질 게이트**
   - `pytest -q --cov=aisast --cov-report=xml --cov-report=term-missing`
   - Codecov 업로드 (`codecov/codecov-action@v4`)
   - `mypy aisast` (type check) — 실패 허용 단계 포함해서 점진 도입
   - `pip-audit` 실행 (의존성 CVE 스캔)
6. **재현성**
   - `uv pip compile pyproject.toml -o requirements.lock` 생성
   - `.github/dependabot.yml` (pip + npm + github-actions weekly)
7. **문서 스텁**
   - `CONTRIBUTING.md` (플러그인/룰 작성 HOW-TO 스켈레톤)
   - `SECURITY.md` (신고 이메일, SLA 스텁)

#### 수용 기준
- Critical 버그 3종 해결 (merge, pipeline, Dockerfile root)
- CI 커버리지 리포트 Codecov 에 표시
- Docker 이미지 non-root 실행 확인
- 기존 테스트 전원 통과

---

### v0.5.0 — 관측성 · 성능 · 확장성 기반 (3~4주)

> **목표**: 프로덕션 운영 최소 요건 달성.

#### 5.1 관측성 (Observability)
- `prometheus-client` 추가 → FastAPI `/metrics` 엔드포인트
  - 엔진별 실행 시간 히스토그램, Finding 생성 카운터, Triage 비용 카운터, DB 쿼리 지연 시간
- `opentelemetry-sdk` + `opentelemetry-instrumentation-fastapi` + `-celery` + `-sqlalchemy`
  - OTLP exporter (cloud 프로파일 기본 ON, 환경변수 토글)
- `aisast/utils/logging.py` 에 JSON 포맷 옵션 추가 (cloud 기본)
- `/health` → `/livez` + `/readyz` 분리, DB / Redis / Celery broker ping 포함

#### 5.2 DB 성능
- Alembic 마이그레이션 추가 — **복합 인덱스 7개**
  - `ix_findings_scan_severity_status (scan_id, severity, status)`
  - `ix_findings_mois_id (mois_id)`
  - `ix_findings_finding_hash (finding_hash)`
  - `ix_scans_project_status_created (project_id, status, created_at DESC)`
  - `ix_audit_logs_user_created (user_id, created_at DESC)`
  - `ix_suppression_rules_project_kind (project_id, kind)`
  - `ix_triage_records_finding_id (finding_id)` — 이미 unique 이지만 명시
- Repo 레이어에 eager loading 명시 (`selectinload(Scan.findings)`, `joinedload(Finding.triage)`)
- `finding_service.search` — 대규모 경로에 `(created_at, id)` seek 페이지네이션 옵션

#### 5.3 Triage 병렬화 · 캐싱
- Celery 태스크 분리: `triage_batch_task(scan_id, finding_ids)` — N개 워커 병렬
- Redis 캐시 — 키: `triage:{hash(rule_id + file_path + start_line + snippet)}`, TTL 24h
- `build_client()` 에 `tenacity` 기반 exponential backoff + 서킷브레이커
- Anthropic token counting (`client.messages.count_tokens`) → 예산 초과 시 skip

#### 5.4 파이프라인 견고성
- `run_scan_task` 에 `autoretry_for=(EngineUnavailable, subprocess.TimeoutExpired)`, `max_retries=2`, `retry_backoff=True`, `acks_late=True`
- 진행률 — Celery `update_state(state="PROGRESS", meta={"engine": name, "progress": pct, "phase": label})`
- `/api/scans/{id}/status` → 기존 HTTP polling 유지 + `/api/scans/{id}/events` SSE 엔드포인트 추가
- 엔진별 개별 `task_soft_time_limit` 오버라이드

#### 5.5 인증 강화
- JWT payload 에 `iat`, `jti` (UUID), `aud`, `iss` 추가
- **Refresh token** — 쿠키 `HttpOnly; SameSite=Strict; Secure`, 회전(rotation) 전략
- Redis 기반 **토큰 블랙리스트** (`jti → exp` 저장)
- `slowapi` → **Redis 백엔드** 전환 (`storage_uri=redis://...`)
- CSRF 토큰 미들웨어 (double-submit cookie 또는 Synchronizer Token Pattern)
- CSP `unsafe-inline` 제거 → nonce 기반 (`Content-Security-Policy: script-src 'nonce-{rand}'`)

#### 수용 기준
- Grafana 대시보드에서 `/metrics` 수집 가능
- 10만 Finding 기준 `finding_service.search` p95 < 200ms
- 1000 findings 기준 triage p95 < 3분
- JWT refresh 플로우 E2E 테스트 통과
- Redis rate limit 다중 인스턴스 테스트 통과

---

### v0.6.0 — 룰 커버리지 확대 & 멀티테넌시 (4~6주)

> **목표**: "실제로 쓸 수 있는 SAST" 를 만든다.

#### 6.1 룰 확대 (최우선)
- **MOIS 49 → 40+ 커버 목표** (80% 이상)
- 우선순위 순서:
  1. **입력검증 나머지** (SR1-5~10, 12~16) — 대부분이 실무 탐지 가치 최고
  2. **보안기능 나머지** (SR2-1~3, 5, 7, 9~10, 12)
  3. **시간/상태, 에러처리, 코드오류, 캡슐화, API 오용** — 13개
- 언어별 담당자 매트릭스 (Java / Python / JavaScript / TypeScript / Go / Kotlin / C#)
- CodeQL 쿼리 팩 추가 — **최소 10개**
  - `sql-injection-taint.ql`, `deserialization.ql`, `path-traversal-taint.ql`, `crypto-weak.ql`, `xxe.ql`, `ssrf.ql`, `command-injection-taint.ql`, `open-redirect.ql`, `ldap-injection.ql`, `toctou.ql`(기존)
- 각 룰에 `metadata.remediation` 필드 (조치 코드 예시 인라인)
- **룰 단위 테스트 스위트**: `tests/fixtures/vulnerable-samples/{lang}/{rule_id}/{positive,negative}.*`

#### 6.2 멀티테넌시
- `Organization` 모델 + 전 테이블 `organization_id` FK
- Repo 믹스인 `OrganizationScopedRepo` — 모든 쿼리에 `WHERE organization_id = :org` 강제
- JWT payload 에 `org_id`, 라우트 데코레이터 `@require_org_access`
- Alembic 마이그레이션 — 기존 데이터는 `default-org` (id=1) 로 할당
- **데이터 교차 접근 방지 E2E 테스트** — user@orgA 가 orgB resource 접근 시 404

#### 6.3 테스트 강화
- **엔진 실제 실행 통합 테스트** (pytest marker `@pytest.mark.engine`, CI 에서 semgrep / bandit / eslint 실제 호출)
- **Celery 워커 통합 테스트** (`pytest-celery` 또는 `docker-compose.test.yml` 기반 real Redis)
- **Playwright E2E** — 5개 핵심 플로우
  1. 로그인 → 프로젝트 생성 → 스캔 → Finding 목록 → 리포트 다운로드
  2. 관리자 어카운트 발급 → 일반 사용자 로그인
  3. Gate policy 설정 → 임계값 초과 → CI 차단
  4. Suppression rule 생성 → 재스캔 → 제외 확인
  5. NL 검색 (`/ask`) → 결과 확인
- **SARIF fixture 10개** (각 엔진 × 각 언어 실제 출력)

#### 수용 기준
- MOIS 40 항목 이상 자동 탐지 검증
- org_id 격리 E2E 전 케이스 통과
- Playwright 5 플로우 통과
- 엔진 통합 테스트 CI 통과

---

### v0.7.0 — 생태계 통합 (4~6주)

> **목표**: 개발자 일상에 녹아드는 SAST.

- **VS Code 확장** — LSP 기반, inline 경고, 로컬 미리보기, 원격 API 연동
- **GitHub Action** (`aisast-action@v1`), **GitLab CI 템플릿**, **Jenkins 플러그인** — 최소 2개 실배포
- **PR 통합 UI** — GitHub Webhook → 자동 스캔 → PR comment / check status → diff 링크
- **WebSocket/SSE 실시간 진행률** — 프론트 `ScanDetail` polling 제거
- **프론트 재작업**
  - React Query 도입 (페이지별 중복 state 제거)
  - `ErrorBoundary` + toast (`sonner` 또는 `react-hot-toast`)
  - 다크모드 토글 (`darkMode: 'class'`)
  - a11y 기본 — `aria-label`, `role`, 키보드 내비게이션
  - i18next 도입 (한/영), `name_en` 활용
- **Code viewer** — `highlight.js` / `shiki` + 라인 넘버 + ±20줄 컨텍스트
- **Diff 뷰어** — `react-diff-viewer` side-by-side

---

### v1.0.0 — KISA CC 인증 준비 (2~3개월)

> **목표**: 공식 인증 트랙 진입 완료.

- **MOIS 49 전 항목 커버** (100%)
- **PDF 리포트 MOIS 공식 포맷 준수** — WeasyPrint CSS 템플릿
  - 표지 / 목차 / 진단 개요 / 점검표 커버리지 / 상세 결과 (항목별) / 조치 권고 / 부록 (CWE/CVE 참조)
- **SBOM 생성** (CycloneDX) — CI 에서 자동 생성, 릴리즈 첨부
- **컨테이너 이미지 서명** (cosign) + SLSA level 2+
- **감사 로그 장기 보관** — S3 export (WORM 모드, Object Lock)
- **보안 정책 공식화**
  - `SECURITY.md` — CVE 신고 이메일, 72h 응답 SLA, 30d 패치 SLA
  - Threat model 문서 (STRIDE 기반)
  - 정기 침투 테스트 결과 공개
- **운영 매뉴얼**
  - 장애 대응 플레이북
  - 백업/복구 절차 (Postgres WAL + MinIO lifecycle)
  - 시크릿 로테이션 가이드 (JWT key, DB password, minio credentials)
  - 버전 업그레이드 절차
- **부하 테스트** (k6 / Locust)
  - 100만 Finding, 1000 동시 사용자, 10분 유지
  - p95 응답시간 목표 < 500ms
- **문서 완성**
  - `docs/API-REFERENCE.md` (수동 큐레이션)
  - `docs/PLUGIN-DEVELOPMENT.md` (entry_points, Registry API, 사례)
  - `CONTRIBUTING.md` 풀 버전
- **KISA CC 요건 체크리스트** (사전 조사 필요, v0.5 중 병행)

---

## 5. 이번 주 Quick Wins (PR 단위)

| PR# | 제목 | 예상 소요 | 대상 파일 |
|---|---|---|---|
| 1 | `fix(merge): prevent LOW beating MEDIUM in severity comparison` | 30분 | `aisast/sarif/merge.py`, `tests/test_sarif_merge.py` (신규) |
| 2 | `fix(pipeline): allow second pass when custom engines include codeql/spotbugs` | 1시간 | `aisast/orchestrator/pipeline.py`, `tests/test_pipeline.py` |
| 3 | `chore(docker): non-root user, HEALTHCHECK, multi-stage build` | 2시간 | `Dockerfile`, `docker-compose.prod.yml`, `deploy/nginx/nginx.conf` |
| 4 | `ci: enable pytest-cov, mypy, pip-audit, dependabot` | 2시간 | `.github/workflows/ci.yml`, `.github/dependabot.yml` (신규) |
| 5 | `feat(db): add composite indexes for findings/scans/audit` | 3시간 | `alembic/versions/20260417_0002_composite_indexes.py` (신규), `aisast/db/models.py` |
| 6 | `chore(deps): add uv lockfile for reproducible builds` | 1시간 | `requirements.lock` (신규), `pyproject.toml`, CI 워크플로 |
| 7 | `docs: add CONTRIBUTING.md and SECURITY.md stubs` | 1시간 | `CONTRIBUTING.md`, `SECURITY.md` (신규) |
| 8 | `refactor(llm): move hardcoded fp_probability=50 to settings` | 30분 | `aisast/config.py`, `aisast/llm/triage.py` |

> 1주 내 8개 PR 모두 머지하면 **v0.4.2 stable** 태그 가능.

---

## 6. 핵심 리스크 & 완화 전략

| # | 리스크 | 영향 | 완화 |
|---|---|---|---|
| 1 | **룰 커버리지 확대가 최대 병목** — 엔진/인프라는 98% 완성인데 룰이 26.5% | SAST 도구의 실제 가치 직결, v0.6 전까지 "쓸 수 없는 도구" 평판 위험 | v0.6 에서 전담 스프린트 + 외부 기여자 온보딩 가이드(`CONTRIBUTING.md`) 선제 작성. 언어별 담당자 지정 |
| 2 | **LLM 비용 폭증** — Triage 캐싱/배치 없이 대형 프로젝트 돌리면 Claude API 비용 통제 불가 | 프로덕션 채택 블로커 | v0.5 에서 먼저 Redis 캐싱 + 배치 + 토큰 예산 구현. 기본값은 `llm_provider=noop` 유지 |
| 3 | **멀티테넌시 마이그레이션 파괴적** — v0.6 에서 모든 쿼리 수정 필요 | 회귀 버그 다발 가능 | v0.5 에서 Repo 패턴 정비 + `OrganizationScopedRepo` 믹스인 먼저 도입. 기존 데이터는 `default-org` 로 무중단 이관 |
| 4 | **CodeQL 라이선스** — GitHub Advanced Security 약관 | 오픈소스 배포 시 상용 사용자 주의 필요 | README 와 USER_GUIDE 에 상업적 사용 시 라이선스 확인 문구 명시. 무료 대안(Joern/Semgrep Pro) 조사 |
| 5 | **KISA CC 요건 구체화 안 됨** — v1.0 목표이지만 실제 체크리스트 없음 | v1.0 까지 요건 변경 시 일정 밀림 | v0.5 중 별도 조사 트랙 — 유사 도구(Sparrow, Deepscan) CC 인증 사례 리서치 |
| 6 | **엔진 바이너리 배포 복잡성** — 사용자가 직접 설치 필요 | 온보딩 마찰 | v0.5~v0.6 중 CodeQL/SpotBugs 포함 "fat" Docker 이미지 빌드 자동화. 엔진 번들 별도 태그(`aisast:v0.5.0-full`) |
| 7 | **프론트 리팩터 vs 기능 개발 트레이드오프** — v0.7 에서 React Query 도입은 파괴적 | 리그레션 | 페이지 단위 점진 이관 — 새로 만드는 페이지부터 React Query 사용, 기존 페이지는 유지 |
| 8 | **데이터 정합성 — `auto_migrate` 프로덕션 사용 금지** | `aisast/db/migrate.py` 가 drop/rename 불가인데 프로덕션에 사용되면 스키마 drift | v0.5 에서 `auto_migrate` 비활성화 (로컬 전용), 프로덕션은 Alembic `upgrade head` 강제. USER_GUIDE 에 명시 |

---

## 7. 부록 — 검증 노트 (Spot Check 결과)

본 문서 작성 시 다음 6개 영역에 대해 병렬 탐색 에이전트 + 직접 코드 확인으로 주장을 검증했다.

### 7.1 Severity 비교 버그 (R3) — 실측

```python
# aisast/sarif/merge.py:51-56
def _prefers(candidate: Finding, existing: Finding) -> bool:
    c_rank = _ENGINE_PRIORITY.get(candidate.engine.lower(), 0)
    e_rank = _ENGINE_PRIORITY.get(existing.engine.lower(), 0)
    if c_rank != e_rank:
        return c_rank > e_rank
    return candidate.severity.value < existing.severity.value  # ← 문자열 비교
```

```python
# Severity 는 str Enum (aisast/mois/catalog.py:14-19)
class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
```

**실제 동작**:
- `"HIGH" < "LOW"` → `True` → HIGH 가 LOW 를 이김 ✓ (우연히 정상)
- `"HIGH" < "MEDIUM"` → `True` → HIGH 가 MEDIUM 을 이김 ✓ (우연히 정상)
- **`"LOW" < "MEDIUM"` → `True` → LOW 가 MEDIUM 을 이김** ✗ (버그)

동일 엔진 우선순위에서 LOW 와 MEDIUM 이 충돌하면 LOW 가 선택된다. 이는 LOW severity finding 이 MEDIUM finding 을 덮어쓰는 현상으로, 심각도 왜곡이 발생한다.

### 7.2 2nd pass 자동 비활성 (O1) — 실측

```python
# aisast/orchestrator/pipeline.py:61-69
first_pass_findings = self._run_pass(
    target, options.engines or FIRST_PASS_ENGINES, "1st"
)

second_pass_findings: list[list[Finding]] = []
if options.enable_second_pass and not options.engines:  # ← and not options.engines
    second_pass_findings = self._run_pass(
        target, SECOND_PASS_ENGINES, "2nd"
    )
```

사용자가 `ScanOptions(engines=("codeql",))` 를 지정해도 `not options.engines` 가 `False` 이므로 2nd pass 가 실행되지 않는다. 결과: CodeQL 만 돌리려는 사용자가 아무 Finding 을 받지 못하는 UX 혼란.

### 7.3 Dockerfile 하드닝 상태 (C1~C3) — 실측

```dockerfile
# Dockerfile (전문)
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git build-essential \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi-dev shared-mime-info \
    openjdk-21-jre-headless \
  && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "semgrep>=1.70"
RUN pip install --no-cache-dir "bandit[sarif]>=1.7"
WORKDIR /app
COPY pyproject.toml README.md ./
COPY aisast ./aisast
COPY rules ./rules
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "aisast.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

확인 사항:
- ❌ `USER` 지시문 없음 → root 실행
- ❌ `HEALTHCHECK` 지시문 없음
- ❌ multi-stage 아님 (`FROM ... AS base` 선언만 있고 실제 stage 분리 없음)
- ❌ build-essential, openjdk, libpango, libcairo 모두 런타임 이미지에 포함 → 이미지 크기 ~1GB

### 7.4 MOIS 룰 커버리지 (R1) — 실측

`rules/opengrep/**/*.yml` 전체 스캔 결과 매핑된 고유 `mois_id` 집합:

```
SR1-1, SR1-2, SR1-3, SR1-4, SR1-11, SR1-17, SR1-18  (입력검증 7개)
SR2-4, SR2-6, SR2-8, SR2-11                          (보안기능 4개)
SR4-1                                                 (에러처리 1개)
SR6-2                                                 (캡슐화 1개)
```

= **13개 고유 항목 / 49개 전체** = **26.5% 커버**

미구현 36개: SR1-5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16 / SR2-1, 2, 3, 5, 7, 9, 10, 12 / SR3 전체 / SR5 전체 / SR7 전체 등.

CodeQL: `rules/codeql/java/toctou.ql` 1개 파일뿐.

### 7.5 CI 커버리지 리포트 부재 (T8, T9) — 실측

```yaml
# .github/workflows/ci.yml:89-91
- name: Run pytest
  if: matrix.mode == 'full'
  run: pytest -q --tb=short
```

`--cov` 플래그 없음. 그런데 `pyproject.toml:94` 에는 `pytest-cov>=5.0` 이 dev 의존성으로 설치됨. 즉 **설치는 되어 있는데 활용되지 않는 상태**. mypy 도 동일 (`mypy>=1.10` 설치되나 CI 실행 없음).

### 7.6 복합 인덱스 부재 (D1) — 실측

`aisast/db/models.py` 전체에서 `__table_args__` 선언 0건. 유일한 제약은:
- `User.email` (unique)
- `Project.name` (unique)
- `RuleSet.name` (unique)
- `TriageRecord.finding_id` (unique)
- `GatePolicy.project_id` (unique)

Finding / Scan / AuditLog / SuppressionRule 에는 **복합 인덱스 · 단일 인덱스 전부 없음**. 수만 건 규모에서 필터/정렬 쿼리 풀스캔.

---

## 문서 유지 정책

- 본 로드맵은 **버전 릴리즈 시마다 갱신**한다.
- v0.4.2 완료 시 "v0.4.2" 섹션을 `## 완료된 마일스톤` 으로 이동.
- 새로운 gap 이 발견되면 3장 매트릭스에 추가 (심각도 표기 필수).
- 우선순위 변경은 PR 에서 토론 후 문서 반영.
