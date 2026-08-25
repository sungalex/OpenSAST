# 변경 이력

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0003](../adr/0003-documentation-architecture.md)).

---

## 변경 이력

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
