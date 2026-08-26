# OpenSAST 문서 색인

문서는 **언제 참인가**로 나뉜다 ([ADR-0007](adr/0007-documentation-architecture.md)).
이 페이지는 `docs/` 아래 **모든 문서가 어느 성격에 속하는지** 한 곳에서 보여준다.
분류되지 않은 문서가 생기면 여기 추가한다 — 색인에 없는 문서는 아무도 갱신
책임을 지지 않는다.

## 성격별 규칙

| 성격 | 참인 시점 | 위치 | 갱신 계기 |
|---|---|---|---|
| **As-built** — 지금 존재하는 것 | 항상 | `ARCHITECTURE.md` | 동작을 바꾸는 모든 PR |
| **Decision** — 왜 그렇게 했는가 | 결정 시점 고정 | `adr/NNNN-*.md` | 추가만 (수정은 Superseded 로) |
| **Plan** — 하려는 것 | 계획 기준일 | `ROADMAP.md`, `plan/` | 릴리스 |
| **Assessment** — 그때 이랬다 | 감사 시점 고정 | `reviews/YYYY-MM-DD-*.md` | **없음 (동결)** |
| **Reference** — 사용법 | 항상 | `guide/*.md` | 기능 변경 |

## 전체 목록

### As-built

| 문서 | 내용 |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | 현재 구조. 코드와 어긋나면 **코드가 정본**이다 |
| [`../CLAUDE.md`](../CLAUDE.md) | ARCHITECTURE 의 요약. 두 번째 진실의 원천이 아니다 |

### Decision — [`adr/`](adr/README.md)

목록·상태·번호 재배정 기록은 [`adr/README.md`](adr/README.md) 가 가진다.
현재 0001(2026-04 작성, **2026-08-26 Accepted** — 구현 미착수) ·
0002·0004(2026-04, Proposed) / 0005~0008(2026-08-25, Accepted).

### Plan

| 문서 | 성격 | 상태 |
|---|---|---|
| [`ROADMAP.md`](ROADMAP.md) | 살아 있는 백로그 | 릴리스마다 갱신 |
| [`plan/UPGRADE-PLAN-unified-analysis.md`](plan/UPGRADE-PLAN-unified-analysis.md) | ADR-0001 의 실행 계획 (2026-04-23) | 동결 — ADR-0001 은 Accepted 지만 ADR-0002 가 rev.2 로 Accepted 되기 전에는 실행되지 않는다 |
| [`LLM_ENHANCEMENT_PLAN.md`](LLM_ENHANCEMENT_PLAN.md) | LLM 계층 고도화 계획 (2026-04) | 동결 — 살아 있는 항목은 ROADMAP 으로 이관 |

`plan/` 은 ROADMAP 한 줄로 담기지 않는 **다단계 실행 계획**을 둔다. ROADMAP 이
"무엇을" 이라면 `plan/` 은 "어떤 순서로" 다. 계획이 끝나거나 폐기되면 동결
헤더를 붙이고 남긴다 (삭제하지 않는다 — 왜 그 방향을 택했는지가 사라진다).

### Assessment — [`reviews/`](reviews/)

| 문서 | 시점 |
|---|---|
| [`reviews/2026-04-16-gap-audit.md`](reviews/2026-04-16-gap-audit.md) | 계획서 대비 구현 격차 감사 |
| [`reviews/2026-08-25-architecture-review.md`](reviews/2026-08-25-architecture-review.md) | 아키텍처 진단 (C-1~4 · H-1~8 · M-1~7) |

동결 문서다. 사실이 달라져도 고치지 않고, 정정이 필요하면 문서 상단 박스에
정정 사항만 덧붙인다.

### Reference — [`guide/`](guide/README.md)

18개 문서의 목차는 [`guide/README.md`](guide/README.md) 에 있다.

| 문서 | 비고 |
|---|---|
| [`install-windows-wsl2.md`](install-windows-wsl2.md) | Windows(WSL2) 전용 설치. 일반 설치는 [`guide/getting-started.md`](guide/getting-started.md) |
| [`USER_GUIDE.md`](USER_GUIDE.md) | `guide/` 로 분할된 뒤 남은 리디렉션 스텁 |
| [`../.claude/README.md`](../.claude/README.md) | 에이전트 개발조직 운영 규약 — 조직도·위임 규약·스킬·훅. 에이전트가 읽는 요약은 [`../CLAUDE.md`](../CLAUDE.md) |

### Proposal (동결)

| 문서 | 비고 |
|---|---|
| [`오픈소스_SW보안약점_진단도구_개발계획서.md`](오픈소스_SW보안약점_진단도구_개발계획서.md) | 착수 제안서. 법적 기준(§2)과 49개 항목 분류(§2.2)는 여전히 참조 가치가 있다 |

## 문서를 새로 만들 때

1. 위 다섯 성격 중 무엇인지 먼저 정한다. 정할 수 없으면 그 문서는 두 개다.
2. 해당 디렉터리에 넣는다.
3. **이 색인에 추가한다.**
4. 동결 문서라면 상단에 `⚠️ 이 문서는 갱신하지 않는다` 박스와 기준일을 넣는다.
