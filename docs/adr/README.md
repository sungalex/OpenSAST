# 아키텍처 결정 기록 (ADR)

이 디렉터리는 OpenSAST 의 **결정**을 기록한다. "지금 무엇이 있는가" 는
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md), "무엇을 할 것인가" 는
[`docs/ROADMAP.md`](../ROADMAP.md) 가 답한다. 여기는 **"왜 그렇게 했는가"** 다.

## 왜 필요한가

큰 결정이 산문 속 불릿으로만 남으면 근거·대안·결과가 사라진다. 그러면 나중에
그 결정을 **뒤집을 수도 없다** — 무엇을 감수하고 고른 것인지 모르기 때문이다.
KISA CC 인증 트랙에서 설계 근거 추적성은 요구사항이 되기 쉬운 항목이기도 하다.

## 문서 성격과 갱신 규칙

| 성격 | 참인 시점 | 위치 | 갱신 계기 |
|---|---|---|---|
| **As-built** — 지금 존재하는 것 | 항상 | `docs/ARCHITECTURE.md` | 동작을 바꾸는 모든 PR |
| **Decision** — 왜 그렇게 했는가 | 결정 시점 고정 | `docs/adr/NNNN-*.md` | **추가만** |
| **Plan** — 하려는 것 | 계획 기준일 | `docs/ROADMAP.md` | 릴리스 |
| **Assessment** — 그때 이랬다 | 감사 시점 고정 | `docs/reviews/YYYY-MM-DD-*.md` | **없음 (동결)** |
| **Reference** — 사용법 | 항상 | `docs/guide/*.md` | 기능 변경 |

**ADR 은 수정하지 않는다.** 결정이 바뀌면 새 ADR 을 쓰고, 옛 ADR 의 Status 를
`Superseded by ADR-NNNN` 으로만 바꾼다. 결정의 역사가 지워지면 ADR 은 의미가 없다.

## 목록

| # | 제목 | 상태 | 날짜 |
|---|---|---|---|
| [0001](0001-unified-analysis-pipeline.md) | 2-Pass 분석 파이프라인의 단일 오케스트레이션 통합 (rev.3) | **Accepted** | 2026-04-23 (2026-08-26 확정) |
| [0002](0002-joern-version-pinning.md) | Joern 엔진 버전 고정 전략 | Proposed *(전제 노후화 — rev.2 필요)* | 2026-04-24 |
| 0003 | *(결번)* | — | — |
| [0004](0004-engine-version-governance.md) | SAST 엔진 버전 거버넌스 3-Tier 정책 | Proposed *(0002 대기)* | 2026-04-24 |
| [0005](0005-authorization-boundary.md) | 인가 강제 지점을 서비스 계층에서 라우트 계약으로 끌어올린다 | Accepted | 2026-08-25 |
| [0006](0006-configuration-single-source.md) | 설정 진실의 원천을 하나로 만들고 배포 프로파일을 산출물에서 명시한다 | Accepted | 2026-08-25 |
| [0007](0007-documentation-architecture.md) | 문서를 성격별로 재편하고 ADR 을 도입한다 | Accepted | 2026-08-25 |
| [0008](0008-triage-concurrency.md) | Triage 를 동시 실행으로 전환하고 조용한 실패를 없앤다 | Accepted | 2026-08-25 |

**ADR-0001 은 2026-08-26 에 Accepted 로 확정됐다** — CodeQL·ESLint 를 제거하고
Joern 으로 대체한다는 방향은 결정됐다. 다만 **구현은 미착수**이며, 현재 코드는
여전히 CodeQL·ESLint 를 포함한다. ADR 과 `ARCHITECTURE.md` 가 다른 것은 정상이다
— 전자는 결정 시점, 후자는 현재 시점을 말한다.

**0002·0004 는 Proposed 로 남는다.** 0002 는 Joern `v2.0.x` 라인을 전제로 쓰였는데
현행은 `4.0.x`(2026-08-25 기준 v4.0.611)라 rev.2 재작성 없이는 Accepted 가 될 수
없고, 0004 는 그 pilot 에 종속된다. **이 두 건이 풀리기 전에는 엔진 교체 코드에
손대지 않는다** — 버전이 고정되지 않은 엔진은 룰 오동작과 버전 부동을 구분할 수
없게 만든다.

### 번호 재배정 기록 (2026-08-26, 1회성)

2026-08-25 아키텍처 진단의 후속 ADR 4건이 `docs/adr/` 가 비어 있다는 전제로
0001~0004 를 사용했으나, 2026-04 에 작성된 ADR 3건이 이미 그 번호를 쓰고
있었다. 파일명이 `ADR-NNNN-*.md` 와 `NNNN-*.md` 로 달라 충돌이 드러나지 않은
채 머지됐다.

번호는 **작성 순서**가 정한다는 원칙에 따라 4월분이 원래 번호를 유지하고,
8월분을 뒤로 옮겼다. 파일명은 전부 `NNNN-*.md` 로 통일했다.

| 이전 | 이후 |
|---|---|
| `ADR-0001-unified-analysis-pipeline.md` | `0001-unified-analysis-pipeline.md` (번호 불변) |
| `ADR-0002-joern-version-pinning.md` | `0002-joern-version-pinning.md` (번호 불변) |
| `ADR-0004-engine-version-governance.md` | `0004-engine-version-governance.md` (번호 불변) |
| `0001-authorization-boundary.md` | `0005-authorization-boundary.md` |
| `0002-configuration-single-source.md` | `0006-configuration-single-source.md` |
| `0003-documentation-architecture.md` | `0007-documentation-architecture.md` |
| `0004-triage-concurrency.md` | `0008-triage-concurrency.md` |

**이 재배정은 예외다.** "ADR 은 수정하지 않는다" 는 위 규칙은 여전히 유효하며,
번호 충돌이라는 사고를 수습하기 위한 1회성 조치로 여기 기록만 남긴다. 앞으로
새 ADR 은 위 표의 마지막 번호 다음을 쓴다.

## 언제 ADR 을 쓰는가

다음 중 하나에 해당하면 쓴다.

- 되돌리기 어려운 선택 (데이터 모델, 인가 모델, 배포 토폴로지)
- 대안이 실재했고 그중 하나를 골랐을 때
- 나중에 누군가 "왜 이렇게 되어 있지?" 라고 물을 것이 확실할 때
- 겉보기에 이상하지만 이유가 있는 선택 (예: passlib 대신 bcrypt 직접 호출)

라이브러리 버전 올리기, 오타 수정, 명백한 버그 픽스에는 쓰지 않는다.

## 템플릿

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
1. [ ] …
```

## 아직 기록되지 않은 결정

다음은 코드에는 있으나 근거가 문서화되지 않은 결정이다. 해당 영역을 손대는
사람이 ADR 로 남기면 좋다.

- 도메인 모델(`opensast/models.py`)을 SQLAlchemy ORM 과 분리한 이유
- 오브젝트 스토어(S3/MinIO) 대신 파일시스템 bind-mount 를 쓰는 이유
- passlib 대신 `bcrypt` 를 직접 호출하는 이유
- 작업 큐로 Celery 를 고른 이유 (RQ/Dramatiq 대비)
- MOIS 카탈로그를 Python 상수로 두고 YAML 을 오버레이로 얹는 이유
