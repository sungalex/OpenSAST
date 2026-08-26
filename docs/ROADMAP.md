# OpenSAST 로드맵

> **성격**: Plan (계획 기준일 기준으로 참) · **기준일**: 2026-08-25
> **현재 버전**: 0.5.0 (`pyproject.toml` 이 정본)
> **목적**: v1.0(KISA CC 인증 트랙)까지 남은 일을 버전 단위로 정리한다.

## 이 문서의 위치

문서는 성격별로 나뉘어 있다 ([ADR-0007](adr/0007-documentation-architecture.md)).

| 알고 싶은 것 | 볼 곳 |
|---|---|
| 지금 무엇이 있는가 | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| 왜 그렇게 만들었는가 | [`adr/`](adr/README.md) |
| **무엇을 할 것인가** | **이 문서** |
| 어떻게 쓰는가 | [`guide/`](guide/README.md) |
| 그때는 어땠는가 | [`reviews/`](reviews/) |
| **문서 전체 목록** | [`README.md`](README.md) |

**여기에는 완료된 항목을 남기지 않는다.** 완료 항목은 릴리스마다 아래
"완료된 마일스톤" 으로 한 줄 요약만 옮기고, 상세는 ARCHITECTURE 또는 ADR 이
가진다. 과거 감사 결과는 [`reviews/`](reviews/) 에 동결되어 있다.

---

## 1. 남은 일 — 한 줄 요약

> **"룰 커버리지는 93% 에 도달했고 운영 기반과 인가 경계도 정리됐다. 남은 것은
> (1) 생태계 통합(IDE·CI 플러그인), (2) 실제 실행 통합 테스트, (3) KISA CC
> 요건 구체화 세 갈래다."**

---

## 2. v0.6.0 — 검증 신뢰도 (3~4주)

> **목표**: "테스트가 통과한다" 가 "실제로 동작한다" 를 의미하게 만든다.

지금 엔진과 Celery 는 전부 `MagicMock` 뒤에 있다. 단위 테스트가 247개 통과해도
엔진 바이너리 호출 규약이 깨졌는지는 알 수 없다.

### 2.1 실행 통합 테스트

- pytest marker `@pytest.mark.engine` — CI 에서 semgrep / bandit / eslint 실제 호출
- Celery 워커 통합 테스트 (`docker-compose.test.yml` 기반 real Redis + Postgres)
- 룰 단위 테스트 스위트:
  `tests/fixtures/vulnerable-samples/{lang}/{rule_id}/{positive,negative}.*`
- SARIF fixture 확대 — 각 엔진 × 각 언어 실제 출력

### 2.2 엔진 구성 결정 마무리

[ADR-0001](adr/0001-unified-analysis-pipeline.md) 이 2026-08-26 **Accepted** 로
확정됐다 — CodeQL·ESLint 를 제거하고 Joern(Primary) + Opengrep taint mode(Secondary)
로 간다. 남은 것은 실행이고, 그 앞에 버전 고정 문제가 막고 있다.

**선행 — ADR-0002 rev.2 (차단 요인)**

- [ADR-0002](adr/0002-joern-version-pinning.md) 는 Joern `v2.0.x` 라인을 전제로
  쓰였으나 현행은 `4.0.x` 다 (2026-08-25 기준 v4.0.611). 대상 라인 교체 + 4.0
  기준 CLI·DSL breaking change 재조사가 필요하다
- `scripts/joern/select_version.py` + 골든 픽스처 신설 — 버전 선정 절차 자체가 없다
- 선정 결과를 `.env.versions` 에 커밋 (`JOERN_VERSION` / `JOERN_SHA256`)
- 위가 끝나면 [ADR-0004](adr/0004-engine-version-governance.md) 도 함께 Accepted

**실행**

- `opensast/engines/joern.py` 어댑터 신설, 레지스트리·파이프라인 배선
- JS/TS 커버리지를 `rules/opengrep/javascript` 로 이관 후 ESLint 제거
- CodeQL 어댑터 제거 — 그전까지는 미설치 시 자동 skip + 라이선스 경고로 완화
- 단계별 계획은 [`plan/UPGRADE-PLAN-unified-analysis.md`](plan/UPGRADE-PLAN-unified-analysis.md)

> §2.1 의 실행 통합 테스트가 이 작업의 실질적 전제다. 엔진을 교체하면서 회귀를
> 잡을 수단이 없으면 교체 자체가 위험하다.

### 2.3 CI 품질 게이트

- `pytest --cov=opensast --cov-report=xml` + Codecov 업로드
- `ruff check opensast` — 현재 CI 에서 실행되지 않는다. 기준선(2026-08-25 시점
  207건, 대부분 FastAPI `Depends()` 기본값에 대한 B008 오탐)을 먼저 정리하거나
  해당 룰을 config 에서 제외한 뒤 게이트로 승격
- `mypy opensast` — 실패 허용 단계로 점진 도입
- `pip-audit` (의존성 CVE)

### 2.4 스캔 취소 · 진행률

- Celery `revoke/terminate` 경로 — 현재 큐잉된 스캔을 취소할 방법이 없다
- `_run_pass` 에 진행률 콜백 → SSE 로 엔진 단위 진행률 전달
- 프론트 `ScanDetail` 이 SSE 를 구독하도록 전환

### 2.5 남은 파이프라인 견고성

- `engines/base.py` — `TimeoutExpired` / 디스크 부족 / 리소스 오류 구분 처리
- `engines/codeql.py` — `database create` 실패 시 stderr 로깅, DB 상태 검증
- `reports/pdf.py` — WeasyPrint 미설치 시 HTML 을 PDF 인 척 반환하는 동작 제거
  (명시적 오류 또는 `Content-Type` 정직화)

### 수용 기준

- 엔진 통합 테스트 CI 통과 (최소 semgrep · bandit)
- Celery 워커 통합 테스트 통과
- 커버리지 리포트 Codecov 표시
- 스캔 취소 E2E 통과

---

## 3. v0.7.0 — 생태계 통합 (4~6주)

> **목표**: 개발자 일상에 녹아드는 SAST. 계획서에서 약속했으나 미이행 상태인
> 항목들이다.

- **VS Code 확장** — LSP 기반, inline 경고, 로컬 미리보기, 원격 API 연동
- **CI 플러그인** — GitHub Action (`opensast-action@v1`), GitLab CI 템플릿,
  Jenkins 플러그인 중 최소 2개 실배포
- **PR 통합 UI** — GitHub Webhook → 자동 스캔 → PR comment / check status
- **프론트 재작업**
  - React Query 도입 (페이지별 중복 state 제거)
  - `ErrorBoundary` + toast
  - 다크모드 (`darkMode: 'class'`)
  - a11y 기본 — `aria-label`, `role`, 키보드 내비게이션
  - i18next (한/영), `name_en` 활용
- **Code viewer** — `shiki` + 라인 넘버 + ±20줄 컨텍스트
- **Diff 뷰어** — side-by-side

---

## 4. v0.8.0 — 규모와 운영 (3~4주)

> **목표**: 수만~수십만 Finding 규모에서 무너지지 않게 한다.

- **rate limit Redis 백엔드** — slowapi in-memory 는 다중 인스턴스에서 우회된다
- **CSP nonce** — `unsafe-inline` 제거
- **시크릿 관리** — Docker secrets 파일 마운트 또는 Vault/AWS SM 연동
  ([ADR-0006](adr/0006-configuration-single-source.md) 후속)
- **기본 관리자 자격증명 제거** — 현재 `bootstrap_admin_password` 기본값이
  `opensast-admin` 이다. README 에 공개된 문서화된 값이라 "유출" 은 아니지만,
  기본 자격증명이 존재한다는 것 자체가 진단 도구로서 약점이다. 서명 키와 같은
  방식(미설정 시 임의 생성 후 최초 1회 로그 출력, cloud 는 기동 거부)으로
  바꾸되, 온보딩 문서와 테스트 픽스처가 함께 바뀌므로 별도 작업으로 둔다
- **감사 로그 장기 보관** — S3 export (WORM / Object Lock)
- **Finding 조회 seek 페이지네이션** — 현재 커서가 있으나 offset 경로가 병행
- **triage 태스크 분할** — 상한(`triage_max_findings`)으로 자르는 대신 chunked
  task 로 전량 처리 ([ADR-0008](adr/0008-triage-concurrency.md) 후속). 행안부
  대응에서 미판정 잔여가 허용되지 않는다면 이 항목이 v0.7 보다 앞선다
- **`work_dir` 공유 스토리지** — 다중 노드 확장 시 NFS/CSI 전환 검토

---

## 5. v1.0.0 — KISA CC 인증 준비 (2~3개월)

> **목표**: 공식 인증 트랙 진입 완료.

- **MOIS 49 전 항목 커버** — 미커버 3개(SR1-15, SR5-3, SR5-6)는 C/C++ 메모리
  취약점. C/C++ 엔진(cppcheck / clang-tidy / CodeQL cpp) 추가 여부 결정 필요
- **PDF 리포트 MOIS 공식 포맷** — 표지 / 목차 / 진단 개요 / 점검표 커버리지 /
  상세 결과 / 조치 권고 / 부록(CWE·CVE 참조)
- **SBOM** (CycloneDX) — CI 자동 생성, 릴리즈 첨부
- **컨테이너 이미지 서명** (cosign) + SLSA level 2+
- **보안 정책 공식화** — CVE 신고 SLA, STRIDE 기반 threat model, 정기 침투 테스트
- **운영 매뉴얼** — 장애 대응 플레이북, 백업/복구, 시크릿 로테이션, 업그레이드
- **부하 테스트** (k6 / Locust) — 100만 Finding, 1000 동시 사용자, p95 < 500ms
- **문서 완성** — `guide/plugin-development.md`, `CONTRIBUTING.md` 풀 버전
- **KISA CC 요건 체크리스트** — 사전 조사 필요 (유사 도구 인증 사례 리서치)

---

## 6. 핵심 리스크

| # | 리스크 | 영향 | 완화 |
|---|---|---|---|
| 1 | **실행 통합 테스트 부재** — 엔진·Celery 가 전부 목(mock) 뒤에 있다 | 엔진 호출 규약이 깨져도 CI 가 초록. 상용 도구로서 신뢰 문제 | v0.6 최우선. marker 로 분리해 로컬은 빠르게, CI 는 전량 |
| 2 | **LLM 비용** — 대형 프로젝트 triage | 프로덕션 채택 블로커 | 캐시가 실제로 동작하게 배선 완료. 토큰 예산 카운팅은 v0.8 |
| 3 | **CodeQL 라이선스** — GitHub Advanced Security 약관 | 공공·감리 등 상업 진단에 그대로 쓸 수 없다 | **대체 방향은 확정됐다** — [ADR-0001](adr/0001-unified-analysis-pipeline.md) Accepted (2026-08-26). 남은 차단 요인은 [ADR-0002](adr/0002-joern-version-pinning.md) 의 전제 노후화(v2.0.x 기준 → 현행 4.0.x)이며 rev.2 재작성이 필요하다. 그전까지는 CodeQL 미설치 시 자동 skip + [`guide/pipeline-and-engines.md`](guide/pipeline-and-engines.md) 의 라이선스 경고로 완화 |
| 4 | **KISA CC 요건 미구체화** | v1.0 일정 변동 | v0.6 중 별도 조사 트랙 |
| 5 | **엔진 바이너리 배포 복잡성** | 온보딩 마찰 | CodeQL/SpotBugs 포함 "fat" 이미지 별도 태그(`opensast:X.Y-full`) |
| 6 | **triage 상한 정책의 규정 적합성** | 미판정 잔여가 감사에서 문제될 수 있음 | 행안부 대응 관점 확인 후 chunked task 전환 여부 결정 |
| 7 | **`viewer` 역할 동작 변경** | 기존 사용자 워크플로 중단 가능 | RBAC 표대로 정정한 것이므로 릴리스 노트에 명시 |

---

## 7. 완료된 마일스톤

| 버전 | 요약 |
|---|---|
| v0.3.1 | 기본 파이프라인 · MOIS 49 카탈로그 · 리포트 4종 |
| v0.4.x | 플러그인 레지스트리 · 서비스 계층 · 3-프로파일 설정 · 보안 미들웨어 · 계정 잠금 · YAML 카탈로그 오버레이 · 확장 훅 · Alembic 도입 · Dockerfile 하드닝 |
| v0.5.0 | 관측성(`/metrics`, OpenTelemetry, JSON 로깅) · 복합 인덱스 · Refresh token + 블랙리스트 · CSRF · triage 캐시·재시도 · lockfile · dependabot |
| v0.5.1 | **인가 경계 재설계** ([ADR-0005](adr/0005-authorization-boundary.md)) · **설정 단일화 및 프로파일 배선** ([ADR-0006](adr/0006-configuration-single-source.md)) · **문서 재편** ([ADR-0007](adr/0007-documentation-architecture.md)) · **triage 동시 실행** ([ADR-0008](adr/0008-triage-concurrency.md)) · 저장 멱등성 · 경로 봉쇄 · 엔진 동시 실행 |

과거 감사 결과와 그 사후 대조는
[`reviews/2026-04-16-gap-audit.md`](reviews/2026-04-16-gap-audit.md) 및
[`reviews/2026-08-25-architecture-review.md`](reviews/2026-08-25-architecture-review.md)
에 동결되어 있다.

---

## 8. 갱신 규칙

- 이 문서는 **릴리스마다** 갱신한다.
- 완료된 버전 섹션은 §7 에 한 줄로 요약하고 본문에서 **삭제**한다.
  (완료 항목을 취소선으로 남기지 않는다 — 그러면 다시 라이브 백로그가 된다)
- 새로 발견된 gap 은 해당 버전 섹션에 추가한다. 대규모 감사 결과는 이 문서가
  아니라 `reviews/YYYY-MM-DD-*.md` 로 동결 발행하고, 그중 살아 있는 항목만
  여기로 승격한다.
- 되돌리기 어려운 설계 선택이 포함되면 [ADR](adr/README.md) 을 함께 쓴다.
