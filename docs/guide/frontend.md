# 웹 프론트엔드

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 웹 프론트엔드

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
