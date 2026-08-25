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
| [0001](0001-authorization-boundary.md) | 인가 강제 지점을 서비스 계층에서 라우트 계약으로 끌어올린다 | Accepted | 2026-08-25 |
| [0002](0002-configuration-single-source.md) | 설정 진실의 원천을 하나로 만들고 배포 프로파일을 산출물에서 명시한다 | Accepted | 2026-08-25 |
| [0003](0003-documentation-architecture.md) | 문서를 성격별로 재편하고 ADR 을 도입한다 | Accepted | 2026-08-25 |
| [0004](0004-triage-concurrency.md) | Triage 를 동시 실행으로 전환하고 조용한 실패를 없앤다 | Accepted | 2026-08-25 |

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
