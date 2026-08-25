# ADR-0007: 문서를 성격별로 재편하고 ADR 을 도입한다

**Status:** Accepted
**Date:** 2026-08-25
**Deciders:** 메인테이너

## Context

문서 6종이 서로의 일부를 복제하고 있었다.

| 문서 | 규모 | 중복 대상 |
|---|---:|---|
| `docs/USER_GUIDE.md` | 1,926줄 | README, CLAUDE.md, ARCHITECTURE §2.4/§4.3 |
| `docs/ROADMAP.md` | 539줄 | 개발계획서 §8, ARCHITECTURE §8, LLM_ENHANCEMENT_PLAN |
| `docs/오픈소스_SW보안약점_진단도구_개발계획서.md` | 498줄 | ARCHITECTURE §1, CLAUDE.md |
| `docs/ARCHITECTURE.md` | 401줄 | 개발계획서 §3.3, USER_GUIDE §3/§13 |
| `docs/LLM_ENHANCEMENT_PLAN.md` | 230줄 | ROADMAP §3.3 및 §4 |
| `CLAUDE.md` | 77줄 | README, 개발계획서 §9 |

구체적 증상은 세 가지였다.

**1. 로드맵이 셋, LLM 계획이 둘.** 개발계획서 §8 은 개월(Phase 1~4),
ARCHITECTURE §8 은 버전(v0.3.1~v1.0), ROADMAP §4 는 버전+기간(v0.4.2~v1.0).
세 축의 매핑이 없어 "지금 무엇을 하고 있는가" 를 문서로 답할 수 없었다.
"Phase 2" 가 ROADMAP 과 LLM_ENHANCEMENT_PLAN 에서 다른 것을 가리켰다.

**2. Gap 매트릭스가 시점 스냅샷인데 라이브 백로그처럼 읽혔다.** 2026-08-25 에
코드와 대조한 결과, ROADMAP §3 의 항목 중 R3·O4·L2·L4·A1·A2·A7·C1~C3·C7·C8·
D1·D2·T10·T11·DOC1·DOC2 가 **이미 해결**되어 있었는데 미해결로 표시돼 있었다.
R1·R2 만 취소선+✅ 로 갱신되고 나머지는 손대지 않은 상태였다. §7 부록은 더
심해서, 코드 발췌를 **줄 번호와 함께** 인용하는데 그 코드는 이미 바뀌어 있었다
(§7.1 이 인용한 `merge.py:51-56` 의 문자열 비교는 현재 소스에 없다).

**3. ARCHITECTURE 가 as-built 과 as-planned 를 섞었다.** §4.1 은 "향후: Refresh
token" 이라 쓰지만 이미 구현돼 있고, §7 표는 메트릭·트레이스를 `(TODO)` 로
표시하지만 둘 다 동작한다. 반대로 §5.5 설정 오버레이는 단정형으로 서술되지만
코드가 없었다. 독자가 이 문서를 읽고 "무엇이 존재하는가" 를 알 수 없었다 —
아키텍처 문서의 유일한 존재 이유가 무력화된 상태다.

**원인은 규율 부족이 아니다.** ROADMAP 에는 이미 문서 유지 정책이 적혀 있었다
("완료 시 완료된 마일스톤 섹션으로 이동"). 정책이 없는 게 아니라 지켜지지
않았다. 근본 원인은 **분류 체계의 부재**다 — "언제 참인가" 가 다른 세 종류의 글이
한 파일에 섞여 있으면, 갱신 주기가 다르므로 반드시 어긋난다.

## Decision

문서를 **갱신 주기가 같은 것끼리** 묶는다.

| 성격 | 참인 시점 | 위치 | 갱신 계기 |
|---|---|---|---|
| **As-built** — 지금 존재하는 것 | 항상 | `docs/ARCHITECTURE.md` | 동작을 바꾸는 모든 PR |
| **Decision** — 왜 그렇게 했는가 | 결정 시점 고정 | `docs/adr/NNNN-*.md` | 추가만, 수정은 Superseded 로 |
| **Plan** — 하려는 것 | 계획 기준일 | `docs/ROADMAP.md` | 릴리스 |
| **Assessment** — 그때 이랬다 | 감사 시점 고정 | `docs/reviews/YYYY-MM-DD-*.md` | **없음 (동결)** |
| **Reference** — 사용법 | 항상 | `docs/guide/*.md` | 기능 변경 |

### 핵심은 Assessment 의 동결

ROADMAP §3 Gap 매트릭스와 §7 부록은 2026-04-16 시점의 감사 결과다. 이를
`docs/reviews/2026-04-16-gap-audit.md` 로 옮기고 헤더에 **"이 문서는 갱신하지
않는다"** 를 명시한다. 살아 있어야 하는 미해결 항목만 ROADMAP §4 의 버전
섹션으로 승격한다.

이러면 유지 정책을 지킬 필요 자체가 사라진다. **동결 문서는 틀릴 수 없다** —
"2026-04-16 기준" 이라고 선언한 문서가 그 시점의 사실을 담는 것은 영원히 참이다.
규율에 의존하는 대신 구조로 해결한다.

### ARCHITECTURE 는 as-built 만

"향후", "TODO", 버전 로드맵 표(§8)를 전부 걷어내고 ROADMAP 으로 옮긴다. 각 절
끝에 근거 ADR 을 링크한다. 이 문서를 읽은 사람은 **지금 코드가 무엇을 하는지**만
알게 된다.

### USER_GUIDE 는 독자별로 분할

설치 / 설정 / CLI / REST / 운영 / 트러블슈팅이 한 파일에 있었다. 독자가 여섯
종류인데 진입점이 하나였다. `docs/guide/` 아래로 분할하고 `docs/guide/README.md`
가 목차 역할을 한다. 특히:

- REST 레퍼런스는 OpenAPI(`/openapi.json`)와 필연적으로 어긋나므로, 수기 명세
  대신 개요 + 자동 문서 링크로 대체한다.
- DB 스키마 절은 `opensast/db/models.py` 를 정본으로 가리킨다.
- 프로파일 표와 RBAC 표는 각각 `config.py` 와 ARCHITECTURE 를 정본으로 하고
  중복 서술을 링크로 바꾼다.

### 제안서와 LLM 계획

`개발계획서.md` 는 성격상 동결 문서(제안서)다. LLM_ENHANCEMENT_PLAN 도
2026-04 시점 계획이다. 둘 다 상단에 동결 배너와 정본 링크를 붙인다. 살아 있는
항목은 ROADMAP 으로 승격한다.

## Options Considered

| 안 | 유지 비용 | 드리프트 저항 | 평가 |
|---|---|---|---|
| A. 현 구조 유지 + 갱신 규율 강화 | 높음 | 낮음 | 이미 정책이 있었는데 지켜지지 않았다. 같은 실패를 반복한다 |
| **B. 성격별 재편 + Assessment 동결 (채택)** | 낮음 | 높음 | 동결 문서는 틀릴 수 없다. 규율이 아니라 구조로 해결 |
| C. 전부 통합해 단일 문서화 | 중간 | 낮음 | 독자 6종에 진입점 1개 — 지금 문제(USER_GUIDE)의 확대판 |

## Consequences

**쉬워지는 것**

- "지금 무엇이 있는가" 에 답하는 문서가 하나로 특정된다.
- 감사 스냅샷은 동결되므로 갱신 의무가 없다. 새 감사는 새 파일이다.
- 결정의 근거·대안·결과가 남아, 나중에 결정을 **뒤집을 수 있다.**

**어려워지는 것**

- 초기 이관 작업(반나절~하루).
- ADR 작성이 큰 PR 의 새 절차로 추가된다. 언제 쓰는지는
  [`docs/adr/README.md`](README.md) 에 명시했다.
- 문서가 여러 파일로 나뉘어 grep 한 번으로 전부 훑기는 어려워진다.
  `docs/guide/README.md` 목차가 이를 보완한다.

**다시 볼 것**

- REST 레퍼런스를 OpenAPI 자동 생성으로 대체했으므로, `/openapi.json` 이
  cloud 프로파일에서 비활성이라는 점과 충돌한다. 공개 문서 사이트를 만들 때
  빌드 타임 스키마 덤프가 필요하다.
- `CLAUDE.md` 는 에이전트용 요약이라 성격상 As-built 의 축약본이다. 지금은
  수기 유지하지만, 분량이 늘면 ARCHITECTURE 에서 생성하는 편이 낫다.

## Action Items

1. [x] `docs/adr/` 개설 + README(정책·템플릿·미기록 결정 목록)
2. [x] ROADMAP §3/§7 → `docs/reviews/2026-04-16-gap-audit.md` 동결 이관
3. [x] ROADMAP 을 완료 마일스톤 + 남은 계획으로 재작성, 버전 표기 통일
4. [x] ARCHITECTURE 를 as-built 로 재작성, ADR 링크 추가
5. [x] USER_GUIDE 를 `docs/guide/` 로 분할 + 목차 신설
6. [x] 개발계획서·LLM_ENHANCEMENT_PLAN 에 동결 배너
7. [x] README·CLAUDE.md 의 버전·프로파일·문서 지도 정정
