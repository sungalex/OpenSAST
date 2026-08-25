# 상용 SAST 대비 기능 비교

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 상용 솔루션 SAST 대비 기능 비교

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
