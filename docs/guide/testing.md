# 테스트

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 테스트

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
