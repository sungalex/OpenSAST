# CLAUDE.md

**OpenSAST** — 행정안전부 「소프트웨어 보안약점 진단가이드」 구현단계 **49개 항목**을
커버하는 다중 엔진 SAST 오케스트레이터. Python 3.12 · FastAPI · Celery · React.

이 파일은 **항상 참인 것**만 담는다. 경로별 상세 규칙은 `.claude/rules/` 가
해당 파일을 열 때 자동으로 붙고, 절차는 `.claude/skills/` 가 호출될 때 붙는다.

## 어디가 정본인가

| 질문 | 문서 |
|---|---|
| 지금 무엇이 있는가 | `docs/ARCHITECTURE.md` (as-built) |
| 왜 그렇게 만들었는가 | `docs/adr/` ([색인](docs/adr/README.md)) |
| 무엇을 할 것인가 | `docs/ROADMAP.md` |
| 어떻게 쓰는가 | `docs/guide/` |
| 그때는 어땠는가 | `docs/reviews/` (동결) |
| 모든 문서, 성격별 | `docs/README.md` |

**코드와 문서가 어긋나면 코드가 정본이다.** 이 파일은 ARCHITECTURE 의 요약이지
두 번째 진실의 원천이 아니다.

## 개발 조직 — 경로가 담당을 정한다

| 경로 | 담당 에이전트 |
|---|---|
| `rules/**`, `opensast/mois/**` | `rule-engineer` |
| `opensast/{engines,orchestrator,sarif,llm,reports}/**` | `engine-engineer` |
| `opensast/{api,services,db}/**`, `config.py`, `alembic/**` | `api-engineer` |
| `frontend/**` | `frontend-engineer` |
| `tests/**`, `.github/workflows/**` | `qa-verifier` |
| `docs/adr/**`, `docs/ROADMAP.md`, `docs/plan/**` | `architect` |
| `docs/ARCHITECTURE.md`, `docs/guide/**`, `README.md` | `docs-curator` |
| git · PR · 버전 · 릴리스 | `release-manager` |
| 변경분 보안 리뷰 (수정하지 않음) | `security-auditor` |

**운영 규약**

- 한 작업에 한 담당. 두 영역에 걸치면 **작업을 쪼갠다**.
- 순서는 **구현 → 검증(`qa-verifier`) → 리뷰(`security-auditor`) → 문서(`docs-curator`)
  → 릴리스(`release-manager`)**. 건너뛰지 않는다.
- 되돌리기 어려운 선택·엔진 구성 변경·MOIS 카탈로그 변경은 **`architect` 가 먼저**다.
  구현부터 시작하지 않는다.
- `security-auditor` 는 코드를 고치지 않는다. 지적 사항은 원래 담당에게 되돌린다.
- 전체 조직도와 위임 규약: `.claude/README.md`. 작업 배정은 `/assign` 으로 시작한다.

## 절대 규칙

이 일곱 가지는 어길 경우 되돌리기 어렵다. 일부는 `.claude/hooks/` 가 기계적으로 막는다.

1. **서비스는 `ActorContext` 없이 만들지 않는다.** `None` 을 넘기면 `TypeError` 다.
   라우트 안에서 `select(models.X)` 를 쓰지 않는다 — 테넌트 데이터를 만지는 모든
   경로는 서비스를 경유한다. `_org_filter()` 는 deny-by-default 다 (ADR-0005).
2. **설정의 단일 소스는 `opensast/config.py` 다.** 한계값·타임아웃·경로를 서비스나
   미들웨어에 하드코딩하지 않는다 (ADR-0006).
3. **결과를 조용히 줄이지 않는다.** 2차 Pass 생략이나 triage 상한은
   `ScanResult.notes` 에 남는다. LLM triage 는 원본 Finding 을 **제거하지 않고
   주석만 단다** — 행안부 대응에서 도구가 결과를 지우면 감리 근거가 무너진다.
4. **의도된 취약 코드를 고치지 않는다.** `tests/vulnerable-samples/` 와
   `tests/test_engine_integration.py` 는 탐지력의 근거다. 스캐너 예외는
   `.gitguardian.yaml` 에 **경로로만** 둔다 (탐지기 단위 비활성화 금지).
5. **시크릿 리터럴을 만들지 않는다.** 테스트 자격증명은 `tests/_credentials.py` 에서
   런타임 생성한다. `*_PASSWORD` 류 식별자가 있는 줄에 따옴표 문자열을 같이 두지
   않는다 — 시크릿 스캐너가 그 모양을 매칭한다.
6. **문서는 성격을 정하고 `docs/README.md` 에 등록한다.** 등록되지 않은 문서는
   아무도 갱신 책임을 지지 않는다. **ADR 은 수정하지 않는다** — 새 ADR 을 쓰고 옛
   ADR 의 Status 만 `Superseded by ADR-NNNN` 으로 바꾼다. 새 ADR 번호는
   `docs/adr/README.md` 에서 **다음 미사용 번호**를 확인하고 쓴다 (0003 은 결번,
   과거 번호 충돌로 1회성 재배정 이력이 있다) (ADR-0007).
7. **`master` 를 직접 조작하지 않는다.** 브랜치 → PR → squash merge → 브랜치 삭제
   (`/ship` 스킬이 이 절차를 담고 있다).
   `--force` 푸시 금지. 이력이 꼬이면 되살리지 말고 브랜치를 새로 만든다.
   PR 전에 **`pytest` 전량 통과**를 확인한다.

공통: 타임스탬프는 timezone-aware UTC. 경로 봉쇄는 `Path.is_relative_to()`
(문자열 prefix 비교 금지). 실패는 단위별로 격리하고 **로깅한다** — `except: pass` 금지.

## 구조 (요약)

- **2-Pass 분석**: 1차 Opengrep·Bandit·ESLint·gosec(동시 실행) → 2차 CodeQL·SpotBugs
  → 3단계 LLM triage(Ollama+Gemma 오프라인 / Claude API 온라인). 구성 정본은
  `opensast/engines/registry.py`.
  **엔진 구성은 바뀔 예정이다**: ADR-0001(Accepted 2026-08-26)이 CodeQL·ESLint 를
  제거하고 Joern(Primary) + Opengrep taint mode(Secondary)로 간다고 결정했다.
  **구현은 미착수** — ADR-0002 가 rev.2 로 재작성돼 Accepted 되기 전에는 CodeQL·ESLint
  어댑터를 제거하지 않는다 (0002 는 Joern v2.0.x 를 전제하나 현행은 4.0.x, 0004 는 여기 종속).
  ADR 과 ARCHITECTURE 가 다른 것은 정상이다 — 전자는 결정 시점, 후자는 현재 시점을 말한다.
- **49개 항목**의 단일 소스는 `opensast/mois/catalog.py` (정확히 49).
  현재 커버리지 **46/49** — 미커버 SR1-15·SR5-3·SR5-6 은 C/C++ 메모리 취약점으로
  지원 언어 밖이다.
- **배포 프로파일** `OPENSAST_PROFILE`: `local`(기본, 보안 완화) / `docker` /
  `cloud`(docs 비활성, 약한 시크릿·빈 CORS 로는 기동 거부).
- **버전 정본은 `pyproject.toml`**.

## 지금의 우선순위 (ROADMAP)

**v0.6 검증 신뢰도**가 최우선이다 — 엔진과 Celery 가 전부 `MagicMock` 뒤에 있어
**"테스트가 통과한다"가 "실제로 동작한다"를 의미하지 않는다.** 실행 통합
테스트(`@pytest.mark.engine`, `celery_integration`), 엔진 구성 결정(ADR-0001/0002/0004),
CI 품질 게이트, 스캔 취소·진행률이 여기에 속한다. 이후 v0.7 생태계 통합 →
v0.8 규모·운영 → v1.0 KISA CC 인증 준비.

## 자주 쓰는 명령

```bash
.venv/bin/python -m pytest -q --tb=short          # 전량 (~90s) — 모든 변경의 최소 기준
.venv/bin/python -m pytest -m engine -q           # 실제 엔진 바이너리 필요 (기본 제외)
.venv/bin/python -m pytest -m celery_integration -q
cd frontend && npm test && npx tsc -b --noEmit
semgrep --validate --config rules/opengrep        # 룰 문법
opensast list-mois | opensast engines             # 카탈로그 / 설치된 엔진
```

기본 `addopts` 가 `-m 'not engine and not celery_integration'` 이므로 무거운
테스트에는 반드시 marker 를 단다.
