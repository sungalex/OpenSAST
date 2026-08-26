---
name: adr
description: 아키텍처 결정 기록(ADR)을 새로 쓰거나 상태를 전환할 때의 절차. 번호 배정, 템플릿, 대안 비교표, Superseded 처리, 색인 등록까지. Use when documenting a hard-to-reverse design decision, accepting/rejecting a proposed ADR, or superseding one.
argument-hint: [결정 주제 또는 ADR 번호]
allowed-tools: Read Write Edit Grep Glob Bash(ls *) Bash(cat *)
---

# ADR 작성 · 상태 전환 절차

대상: $ARGUMENTS

## 0. 정말 ADR 인가

**쓴다**: 되돌리기 어려운 선택(데이터 모델·인가 모델·배포 토폴로지) · 대안이
실재했고 그중 하나를 골랐을 때 · 나중에 "왜 이렇게 되어 있지?" 를 물을 것이
확실할 때 · 겉보기에 이상하지만 이유가 있는 선택.

**쓰지 않는다**: 라이브러리 버전 올리기 · 오타 · 명백한 버그 픽스.

## 1. 번호를 확인한다 — 건너뛰지 않는다

```bash
ls docs/adr/
grep -n "^| \[0" docs/adr/README.md
```

디렉터리는 **비어 있지 않다**. 0001·0002·0004 는 2026-04, 0005~0008 은
2026-08, **0003 은 결번**이다. 과거에 "비어 있다"고 가정한 탓에 번호 충돌이
나 1회성 재배정을 해야 했고, 그 기록이 `docs/adr/README.md` 에 남아 있다.
**목록의 마지막 번호 다음**을 쓴다. 파일명은 `NNNN-kebab-title.md`.

## 2. 템플릿

```markdown
# ADR-NNNN: [결정을 한 문장으로]

**Status:** Proposed | Accepted | Superseded by ADR-NNNN
**Date:** YYYY-MM-DD
**Deciders:** [승인이 필요한 사람]

## Context
어떤 상황인가. 어떤 힘들이 작용하는가. (문제 서술 — 해법은 아직 쓰지 않는다)

## Decision
무엇을 바꾸는가. 현재형 능동태로.

## Options Considered
| 안 | [평가축1] | [평가축2] | 평가 |
|---|---|---|---|
| A. … | | | |
| **B. … (채택)** | | | |

## Consequences
- 쉬워지는 것:
- 어려워지는 것:
- 다시 볼 것:

## Action Items
1. [ ] … (담당 에이전트를 함께 적는다)
```

**품질 기준 3가지**

1. Options 가 하나뿐이면 ADR 이 아니라 설명문이다. 실제로 검토한 대안을 쓴다.
2. "어려워지는 것"이 비어 있으면 아직 결정을 이해하지 못한 것이다.
3. Action Items 에 담당(에이전트/사람)이 없으면 결정이 실행되지 않는다.

## 3. 상태를 전환할 때

- **Proposed → Accepted**: 헤더의 `Status` 를 바꾸고, `docs/adr/README.md` 의
  목록 표와 그 아래 설명 문단, `docs/ROADMAP.md` 의 해당 절을 **같은 PR 에서**
  함께 맞춘다. 문서만 바뀌고 코드가 그대로면 "무엇이 진짜인가"가 흐려지므로,
  구현 미착수라면 그 사실을 명시한다.
- **결정이 뒤집힐 때**: 기존 ADR 본문을 고치지 않는다. **새 ADR 을 쓰고**, 옛
  ADR 의 `Status` 만 `Superseded by ADR-NNNN` 으로 바꾼다.

## 4. 색인을 갱신한다 (누락 금지)

- `docs/adr/README.md` 의 목록 표
- `docs/README.md` 의 Decision 절
- 관련 있으면 `docs/ROADMAP.md`, `CLAUDE.md`

## 지금 열려 있는 결정 (2026-08)

| ADR | 상태 | 남은 일 |
|---|---|---|
| 0001 Joern 대체 / CodeQL·ESLint 제거 | **Accepted (2026-08-26)** — 구현 미착수 | 0002 가 풀린 뒤 실행 |
| 0002 Joern 버전 고정 | Proposed *(전제 노후화)* | **rev.2 재작성** — 본문이 Joern `v2.0.x` 전제인데 현행은 `4.0.x`. 엔진 교체 전체의 차단 요인 |
| 0004 엔진 버전 거버넌스 3-Tier | Proposed | 0002 pilot 에 종속 |

상태를 전환했다면 **네 곳이 모두 맞는지** 확인한다:
`docs/adr/README.md` · `docs/README.md` · `docs/ROADMAP.md` · 루트 `CLAUDE.md`.
