# OpenSAST 사용자 가이드

> **성격**: Reference — 사용법. 항상 현재 코드를 기준으로 참이어야 한다.
> 기능이 바뀌면 해당 문서를 함께 고친다.

이 가이드는 예전 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 나눈 것이다.
독자가 여섯 종류인데 진입점이 하나여서, 필요한 절을 찾기도 어렵고 어긋난 곳을
발견하기도 어려웠다 ([ADR-0007](../adr/0007-documentation-architecture.md)).

## 처음 오셨다면

1. [설치와 첫 실행](getting-started.md) — 로컬 개발 환경, Docker Compose,
   최초 로그인 계정
2. [CLI 레퍼런스](cli.md) — `opensast scan` / `serve` / `list-mois` / `engines` /
   `report`
3. [분석 파이프라인과 엔진](pipeline-and-engines.md) — 2-Pass 모델, 엔진별 특이사항

## 운영자

| 문서 | 내용 |
|---|---|
| [설정 레퍼런스](configuration.md) | 환경변수 전체. 배포 프로파일, LLM, 엔진 경로 |
| [인증과 권한](auth-and-rbac.md) | 로그인, 토큰, 역할별 권한 |
| [데이터베이스](database.md) | 스키마 개요, 마이그레이션 |
| [엔터프라이즈 기능](enterprise.md) | 멀티테넌시, 관측성, 게이트 정책 |
| [트러블슈팅](troubleshooting.md) | 자주 겪는 문제와 해결 |

## 진단 담당자

| 문서 | 내용 |
|---|---|
| [MOIS 49개 항목 카탈로그](mois-catalog.md) | 항목 ↔ CWE ↔ 엔진 매핑 |
| [커스텀 룰 작성](custom-rules.md) | Opengrep YAML, CodeQL 쿼리 |
| [LLM 오탐 필터링](llm-triage.md) | triage 동작, 응답 스키마, 프로바이더 |
| [리포트 포맷](reports.md) | SARIF / HTML / Excel / PDF |
| [웹 프론트엔드](frontend.md) | 화면 구성, 이슈 워크플로 |

## 개발자 / 통합

| 문서 | 내용 |
|---|---|
| [REST API](api.md) | 엔드포인트 지도. **상세 스펙은 OpenAPI 가 정본** |
| [확장 / 커스터마이징](extending.md) | 플러그인, 훅, 오버레이 |
| [테스트](testing.md) | pytest, Vitest, CI |
| [상용 SAST 대비 비교](comparison.md) | 기능 매트릭스 |
| [변경 이력](changelog.md) | 버전별 변경 내역 |

---

## 정본이 코드인 항목

문서와 코드가 어긋났을 때 **코드가 옳은** 항목들이다. 이 가이드는 그것을
서술할 뿐이며, 세부 사실은 아래를 직접 확인한다.

| 주제 | 정본 |
|---|---|
| 설정 항목·기본값 | `opensast/config.py` |
| REST 엔드포인트·스키마 | `/openapi.json` (서버 실행 후) |
| DB 스키마 | `opensast/db/models.py`, `alembic/versions/` |
| RBAC 강제 지점 | `opensast/api/deps.py`, 각 서비스의 `require_role()` |
| MOIS 49 카탈로그 | `opensast/mois/catalog.py` |
| 엔진 목록·바이너리 | `opensast/engines/registry.py` |

## 다른 문서

| 알고 싶은 것 | 문서 |
|---|---|
| 지금 무엇이 있는가 | [`../ARCHITECTURE.md`](../ARCHITECTURE.md) |
| 왜 그렇게 만들었는가 | [`../adr/`](../adr/README.md) |
| 무엇을 할 것인가 | [`../ROADMAP.md`](../ROADMAP.md) |
| 그때는 어땠는가 | [`../reviews/`](../reviews/) |
