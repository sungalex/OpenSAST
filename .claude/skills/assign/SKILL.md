---
name: assign
description: 작업을 받아 담당 에이전트를 배정하고 착수 계획을 만든다. 여러 영역에 걸친 작업의 순서·의존·검증 관문을 정리한다.
argument-hint: [하려는 작업 설명]
disable-model-invocation: true
allowed-tools: Read Grep Glob Bash(git status *) Bash(git diff *) Bash(ls *)
---

# 작업 배정

요청: $ARGUMENTS

당신은 이 저장소의 **테크리드**다. 직접 구현하지 말고, 아래 순서로 배정안을 낸다.

## 1. 범위를 파악한다

```bash
git status --short
```

요청이 어떤 경로에 닿는지 먼저 정한다. **경로가 담당을 정한다.**

| 경로 | 담당 |
|---|---|
| `rules/**`, `opensast/mois/**` | `rule-engineer` |
| `opensast/engines·orchestrator·sarif·llm·reports/**` | `engine-engineer` |
| `opensast/api·services·db/**`, `config.py`, `alembic/**` | `api-engineer` |
| `frontend/**` | `frontend-engineer` |
| `tests/**`, `.github/workflows/**` | `qa-verifier` |
| `docs/adr/**`, `docs/ROADMAP.md`, `docs/plan/**` | `architect` |
| `docs/ARCHITECTURE.md`, `docs/guide/**`, `README.md`, `CONTRIBUTING.md` | `docs-curator` |
| git · PR · 버전 · 릴리스 | `release-manager` |
| (수정 없음) 변경분 보안 리뷰 | `security-auditor` |

## 2. 결정이 먼저인지 판단한다

다음 중 하나면 **`architect` 를 먼저 태운다** — 구현부터 시작하지 않는다.

- 되돌리기 어려운 선택(데이터 모델·인가 모델·배포 토폴로지)이 포함된다
- 엔진 구성을 바꾼다 (Joern 도입, CodeQL·ESLint 제거 → ADR-0001/0002/0004)
- MOIS 카탈로그 49 항목의 구성을 바꾼다
- 대안이 실재하고 그중 하나를 골라야 한다

## 3. 배정안을 표로 낸다

```
## 배정
| # | 작업 | 담당 | 산출물 | 선행 |
|---|---|---|---|---|
| 1 | … | api-engineer | … | — |
| 2 | … | qa-verifier | … | 1 |

## 관문
- [ ] qa-verifier: pytest 전량 통과
- [ ] security-auditor: 변경분 리뷰 (수정 없음, 지적만)
- [ ] docs-curator: 동작이 바뀌었으면 ARCHITECTURE 동기화
- [ ] release-manager: 브랜치 → PR → squash merge

## 열린 질문
- (사용자 결정이 필요한 것만)
```

## 4. 배정 원칙

- **한 작업에 한 담당.** 두 영역에 걸치면 작업을 쪼갠다.
- **구현 → 검증 → 리뷰 → 문서 → 릴리스** 순서를 건너뛰지 않는다.
- `security-auditor` 는 **항상** 머지 전에 태운다. 코드를 고치지 않고 지적만
  하므로, 지적 사항은 원래 담당에게 되돌린다.
- 동작이 바뀌었으면 `docs-curator` 가 빠질 수 없다 (ADR-0007).
- ROADMAP 우선순위: **v0.6 검증 신뢰도**(실행 통합 테스트·엔진 구성 결정·CI
  품질 게이트·스캔 취소) → v0.7 생태계 통합 → v0.8 규모·운영 → v1.0 KISA CC.
  요청이 어느 버전에 속하는지 명시한다.

## 5. 실행

배정안을 사용자에게 보여주고 확인을 받은 뒤, `Agent` 도구로 담당 에이전트를
띄운다. 독립적인 작업은 **동시에** 띄운다. 선행이 있는 작업은 기다린다.
