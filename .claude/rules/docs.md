---
paths:
  - "docs/**/*.md"
  - "README.md"
  - "CONTRIBUTING.md"
  - "SECURITY.md"
---

# 문서 규약 (ADR-0007)

문서는 **언제 참인가**로 나뉜다.

| 성격 | 참인 시점 | 위치 | 갱신 계기 | 소유 |
|---|---|---|---|---|
| **As-built** | 항상 | `docs/ARCHITECTURE.md` | 동작을 바꾸는 모든 PR | docs-curator |
| **Decision** | 결정 시점 고정 | `docs/adr/NNNN-*.md` | **추가만** | architect |
| **Plan** | 계획 기준일 | `docs/ROADMAP.md`, `docs/plan/` | 릴리스 | architect |
| **Assessment** | 감사 시점 고정 | `docs/reviews/YYYY-MM-DD-*.md` | **없음 (동결)** | — |
| **Reference** | 항상 | `docs/guide/*.md` | 기능 변경 | docs-curator |

## 절대 규칙

1. **새 문서는 `docs/README.md` 색인에 등록한다.** 등록되지 않은 문서는 아무도
   갱신 책임을 지지 않고 조용히 썩는다.
2. **성격을 먼저 정한다.** 정할 수 없으면 그 문서는 두 개다 — 쪼갠다.
3. **코드와 문서가 어긋나면 코드가 정본이다.** 문서를 고친다.
4. **`reviews/` 는 동결이다.** 사실이 달라져도 본문을 고치지 않고, 상단 박스에
   정정 사항만 덧붙인다. 새 문서는 상단에 `⚠️ 이 문서는 갱신하지 않는다` 박스와
   기준일을 둔다.
5. **ADR 은 수정하지 않는다.** 결정이 바뀌면 새 ADR 을 쓰고 옛 ADR 의 `Status`
   만 `Superseded by ADR-NNNN` 으로 바꾼다.
6. **ADR 번호는 `docs/adr/README.md` 에서 다음 미사용 번호를 확인하고 쓴다.**
   0001·0002·0004 는 2026-04, 0005~0008 은 2026-08, 0003 은 결번이다. 과거에
   이 확인을 건너뛴 탓에 1회성 번호 재배정이 있었다.
7. **`CLAUDE.md` 는 요약이지 두 번째 진실의 원천이 아니다.** 상세는
   `ARCHITECTURE.md` 에만 둔다.
8. 문서에 넣는 명령·경로·환경변수는 **실제로 실행해 확인한 것만** 쓴다.

## ROADMAP 갱신

완료 항목을 본문에 남기지 않는다. 릴리스마다 §7 "완료된 마일스톤" 에 한 줄로
옮기고 본문에서 **삭제**한다. 취소선으로 남기면 다시 라이브 백로그가 된다.
버전 정본은 `pyproject.toml`.
