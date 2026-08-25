# OpenSAST 아키텍처 진단 — 코드 + 문서

> ## 처리 상태 — 2026-08-25 동일자 반영 완료
>
> **성격**: Assessment (감사 시점 고정). 아래 본문은 **진단 당시의 코드 상태**다.
> 여기 적힌 결함은 같은 날 모두 조치되었으므로, **현재 상태의 근거로 쓰지 말 것.**
>
> - 지금 무엇이 있는가 → [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
> - 조치의 근거 → [ADR-0001](../adr/0001-authorization-boundary.md) ·
>   [ADR-0002](../adr/0002-configuration-single-source.md) ·
>   [ADR-0003](../adr/0003-documentation-architecture.md) ·
>   [ADR-0004](../adr/0004-triage-concurrency.md)
> - 남은 일 → [`../ROADMAP.md`](../ROADMAP.md)
>
> ### ⚠️ 본문 정정 (C-1)
>
> 최초 진단에서 "프로파일이 **어떤** 배포 산출물에서도 활성화되지 않는다" 고
> 적었으나 이는 **부정확**하다. `docker-compose.prod.yml` 은 api·worker 양쪽에
> `OPENSAST_PROFILE: cloud` 를 설정하고 있었다. 진단 시점에 해당 파일이 아직
> 작업 환경에 올라오지 않아 확인하지 못한 것이 원인이다.
>
> 정확한 문제 범위는 다음과 같으며, 아래 C-1 본문은 이에 맞게 고쳤다.
>
> - `docker-compose.yml` (README 가 안내하는 기본 경로)에 프로파일 지정 없음
>   → 팀/온프레미스 표준 배포가 `local` 기본값으로 기동
> - `.env.example` 에 `OPENSAST_PROFILE` 항목 없음
> - `validate_profile()` 의 경고가 로그 WARNING 에 그침 (기동은 성공)
>
> ### 진단 이후 추가로 발견된 결함
>
> | ID | 요약 |
> |---|---|
> | **H-7** | `alembic upgrade head` 가 빈 DB 에서 **항상 실패**했다. 리비전 0001 이 `Base.metadata.create_all()` 로 *현재* 모델을 생성해, 0002 가 추가하려는 인덱스가 이미 존재했다(`index already exists`). 문서가 안내하는 프로덕션 스키마 경로가 한 번도 동작하지 않았다는 뜻이며, `auto_migrate` 가 기동 시 대신 일해 주고 있어 드러나지 않았다. 0001 을 명시적 DDL 로 동결하고, 0002~0004 를 멱등화·SQLite 호환화해 해결 |
> | **H-8** | `alembic/env.py` 가 호출자가 지정한 DB URL 을 무조건 설정값으로 덮어써, 마이그레이션을 다른 DB 로 돌리거나 테스트할 수 없었다 |


> **진단일**: 2026-08-25
> **대상 버전**: pyproject 0.5.0
> **범위**: 백엔드 · 배포 산출물 · 문서 세트
> **성격**: Assessment (시점 고정). **이 문서는 갱신하지 않는다.** 미해결 항목만 ROADMAP 으로 승격한다.

---

## 요약

계층 설계와 확장 지점은 상용 도구 수준으로 잡혀 있다. 문제는 설계가 아니라 **배선**이다.

1. **인가는 설계되어 있으나 강제되지 않는다.** 서비스 계층이 `ActorContext` 로 조직 스코핑·역할 검증을 수행하도록 만들어져 있는데, 라우트 8곳이 actor 없이 서비스를 생성한다. actor 가 없으면 필터가 통과로 평가된다 — 기본값이 "전체 허용" 이다.
2. **3-프로파일 설계가 어떤 배포 산출물에서도 켜지지 않는다.** `OPENSAST_PROFILE` 이 compose · prod compose · `.env.example` 어디에도 없다. 모든 배포가 `local` 기본값(CORS `*`, docs 노출, rate limit off, 약한 시크릿 검사 비활성)으로 뜬다.
3. **문서가 코드보다 뒤에 있으면서 앞에 있는 척한다.** ROADMAP Gap 매트릭스 항목 상당수는 이미 해결됐고, ARCHITECTURE 가 약속한 기능 일부는 구현되지 않았다. 양방향 드리프트다.

---

## Part 1 — 코드 아키텍처

### 1.1 구조적으로 잘 잡힌 부분

- **도메인 모델의 라이브러리 독립성** — `opensast/models.py` 의 `Finding` 이 SQLAlchemy · FastAPI 를 모르기 때문에 CLI · 파이프라인이 웹 스택 없이 단독 동작한다. 폐쇄망 배포에서 실질적 가치가 크다.
- **단일 `Registry[T]` 로 5개 확장 카테고리 통합** — 엔진 · LLM · 리포트 · 레퍼런스 · 훅이 같은 메커니즘을 쓴다. 플러그인 로드 실패가 시스템 전체를 멈추지 않는 격리도 되어 있다.
- **엔진 부재를 정상 경로로 처리** — `EngineUnavailable` 로 미설치 엔진을 건너뛰는 설계 덕분에 부분 설치 환경에서도 파이프라인이 돈다.
- **LLM 이 원본 Finding 을 제거하지 못하게 타입으로 강제** — `triage` 는 필드 추가만 한다. 행안부 지침 대응에서 가장 중요한 제약을 코드 구조로 못 박았다.
- **YAML 오버레이로 카탈로그 교체** — 행안부 개정판 대응이 Python 수정 없이 가능하다. `mois_catalog_path` / `reference_standards_path` 경로는 실제로 동작한다.

### 1.2 결함 — 심각도 순

각 항목의 **증거** 는 소스에서 직접 확인한 위치다.

#### C-1 · Critical — 표준 Docker 배포에서 프로파일이 활성화되지 않는다

*(상단 정정 고지 참조 — 최초 문구는 "어떤 산출물에서도" 였으나 부정확했다)*

ARCHITECTURE 가 가장 강조하는 설계(§2.4, §6)인데, README 가 안내하는 기본 경로(`docker compose up --build`)가 쓰는 `docker-compose.yml` 에는 `OPENSAST_PROFILE` 지정이 없다. `.env.example` 에도 없다. (`docker-compose.prod.yml` 에는 `cloud` 가 지정돼 있다.) 결과적으로 팀/온프레미스 표준 배포가 `Profile.LOCAL` 기본값으로 기동한다 — `cors_origins=["*"]`, `enable_docs=True`, `rate_limit_per_minute=0`, `enforce_strong_secret=False`. 여기에 compose 가 부트스트랩 관리자 자격증명을 평문 기본값으로 주입한다. 즉 가장 널리 쓰일 배포 경로에서 "안전한 기본값" 설계가 무효다.

덧붙여 cloud 프로파일에서도 `validate_profile()` 의 결과가 로그 WARNING 에 그쳐, 약한 시크릿이나 빈 CORS 로도 기동 자체는 성공한다.

> **증거** — `docker-compose.yml` / `.env.example` 에 `OPENSAST_PROFILE` 부재 (`docker-compose.prod.yml` 에는 존재) · `config.py:_PROFILE_DEFAULTS[Profile.LOCAL]` · `docker-compose.yml:56-57`

#### C-2 · Critical — 인가 경계가 라우트에서 끊긴다 (조직 격리 우회)

`BaseService._org_filter()` 는 `actor.organization_id` 가 `None` 이면 `True`(무필터)를 반환한다. 그런데 조회 라우트 8곳이 `ScanService(db)` / `FindingService(db)` 처럼 actor 없이 서비스를 만든다. 타 조직의 스캔 · Finding · 소스 파일이 그대로 읽힌다. `deps.py` 에 준비된 `require_org_access()` 는 라우트에서 **단 한 번도 호출되지 않는다**. 대시보드 5개 엔드포인트는 아예 `_: User = Depends(...)` 로 사용자를 버리고 전역 집계를 반환한다.

> **증거** — `services/base.py:76-80` · `routes/scans.py:112,124,138,160` · `routes/findings.py:42,69,142,164` · `routes/dashboard.py:26,76,100,122,156` · `deps.py:require_org_access` 참조 0건

#### C-3 · Critical — 임의 경로 스캔 + 소스 뷰어 = 워커 호스트 파일 읽기

`POST /api/scans` 는 `source_path` 를 검증 없이 받고 역할 검사도 없다. 어떤 인증 사용자든(`viewer` 포함) `/etc` 나 `/` 를 대상으로 스캔을 큐잉할 수 있다. 이어서 `GET /api/scans/{id}/source?path=...` 가 그 루트 아래 파일을 반환한다. 두 엔드포인트가 합쳐지면 워커 컨테이너 파일시스템 임의 읽기가 된다. ARCHITECTURE §4.3 RBAC 표는 `viewer` 의 스캔 실행을 ✗ 로 규정하지만, API 전체에서 `require_role` 을 쓰는 라우트는 `auth.py:202` 하나뿐이다.

> **증거** — `routes/scans.py:38-56` · `schemas.py:ScanCreate`(source_path 검증자 없음) · `services/scan_service.py:131-166` · `routes/scans.py:150-161`

#### C-4 · Critical — SSE 엔드포인트가 무인증이며 DB 세션을 무기한 점유한다

`GET /api/scans/{scan_id}/events` 에는 인증 의존성이 없다. 스캔 ID 만 알면 누구나 상태를 구독한다. 더해서 이 핸들러는 `get_db` 세션을 잡은 채 2초 간격 폴링 루프를 도는데, 스캔이 `queued` 에 머물면 루프가 끝나지 않는다. 동시 구독 수만큼 커넥션이 고갈된다.

> **증거** — `routes/scans.py:164-186` — 시그니처에 `get_current_user` 없음, `while True` + `asyncio.sleep(2)`

#### H-1 · High — `/ready` 가 존재하지 않는 모듈을 import 해 영구 degraded

readiness 프로브가 `from opensast.worker import celery_app` 을 시도한다. 그런 모듈은 없다(실제 경로는 `opensast.orchestrator.celery_app`). `except Exception` 이 이를 삼켜 `checks["celery"]` 에 ImportError 문자열을 담고, `all_ok` 가 영원히 False 가 된다. Kubernetes 에 올리면 트래픽이 절대 라우팅되지 않는다.

> **증거** — `api/app.py:129` — `opensast/worker.py` 부재 확인

#### H-2 · High — 경로 봉쇄를 문자열 접두사로 검사한다

ZIP 해제와 소스 뷰어 모두 `str(candidate).startswith(str(root))` 로 탈출을 막는다. `/work/sources/ab` 가 루트일 때 `/work/sources/abcd` 가 통과한다. `Path.is_relative_to()` 로 교체해야 한다. 같은 함수에 압축 확대율(zip bomb) 검사도 없다 — 500 MiB 업로드가 디스크를 채울 수 있다.

> **증거** — `services/scan_service.py:351` · `services/scan_service.py:413`

#### H-3 · High — 워커에 `OPENSAST_REDIS_URL` 이 없어 triage 캐시가 완전히 죽어 있다

compose 의 `api` 서비스에는 `OPENSAST_REDIS_URL` 이 있지만 `worker` 에는 없다. 워커는 기본값 `redis://localhost:6379/0` 로 접속을 시도하고 매번 실패한다. `_get_cached` / `_set_cached` 가 `except Exception: return None` / `pass` 로 삼키기 때문에 **로그 한 줄 없이** 캐시가 무효화된다. Finding 하나당 실패 커넥션이 2회 생성되므로 성능도 함께 깎인다. ROADMAP 이 "해결됨" 으로 간주하는 기능이 배포에서는 존재하지 않는 상태다.

> **증거** — `docker-compose.yml:51` vs `:72-77` · `llm/triage.py:_get_cached / _set_cached`

#### H-4 · High — 예외 타입 불일치로 "알 수 없는 엔진" 처리 경로가 죽어 있다

`engine_registry.get()` 은 `PluginError(RuntimeError)` 를 던지는데, `build_engine()` 은 `except KeyError` 로 잡으려 하고, 파이프라인의 `_run_pass` 도 `except KeyError` 로 받는다. 어느 쪽도 걸리지 않으므로 잘못된 엔진 이름 하나가 스캔 전체를 크래시시킨다 — "경고 후 건너뛴다" 는 설계 의도와 반대다.

> **증거** — `plugins/registry.py:get()` → `PluginError` · `engines/registry.py:build_engine` · `orchestrator/pipeline.py:_run_pass`

#### H-5 · High — 비멱등 저장 + 전체 예외 재시도 = Finding 중복 삽입

Celery 태스크가 `autoretry_for=(Exception,)`, `max_retries=2`, `acks_late=True` 로 설정돼 있다. `persist_scan_result()` 는 기존 행을 확인하지 않고 무조건 `session.add` 한다. 저장 도중 워커가 죽거나 soft time limit 에 걸리면 스캔 전체가 재실행되고 Finding 이 2~3배로 쌓인다. 게다가 태스크가 이미 `mark_scan_failed` 로 실패를 기록한 뒤 `raise` 하므로, 재시도 중에도 스캔 상태는 `failed` 로 남아 있다.

> **증거** — `orchestrator/tasks.py:24-33, 60-73` · `db/repo.py:persist_scan_result` — `scan_id` + `finding_hash` 유니크 제약 없음

#### H-6 · High — LLM triage 가 완전 직렬이라 대형 스캔에서 반드시 타임아웃된다

`Triager.triage()` 는 Finding 을 하나씩 순회하며 LLM 을 호출한다. 각 호출은 tenacity 로 최대 3회 재시도하고 타임아웃은 60초다. Finding 1,000개면 낙관적으로도 30분을 넘기는데, `triage_task_soft_time_limit` 은 1,800초다. 배치 · 동시성 · 상한 중 어느 것도 없다. 또한 `except LLMError` 만 잡으므로 그 외 예외(포맷 오류, 파일 접근 등) 하나가 나머지 Finding 의 triage 를 통째로 날린다.

> **증거** — `llm/triage.py:triage()` 루프 · `config.py: llm_timeout_seconds=60, triage_task_soft_time_limit=1800`

#### M-1 · Medium — 병합이 CWE 없는 Finding 을 좌표만으로 합쳐 원본을 잃는다

`merge_findings` 의 중복 키는 `(파일, 라인, CWE 튜플)` 이다. CWE 매핑이 없는 Finding 들은 CWE 튜플이 모두 빈 값이라, 같은 줄에 있는 서로 다른 규칙의 탐지가 하나로 붕괴한다. LLM 에는 "원본 제거 금지" 를 강제해 놓고 병합 단계에서 조용히 버리는 셈이라, 행안부 대응 관점에서 감사 리스크가 있다.

> **증거** — `sarif/merge.py:merge_findings` — `key = (file_path, start_line, tuple(sorted(cwe_ids)))`

#### M-2 · Medium — triage 컨텍스트 수집에 경로 봉쇄가 없다

`_collect_context()` 가 `(source_root / finding.location.file_path).resolve()` 를 봉쇄 검사 없이 읽는다. 엔진이 절대 경로나 `../` 를 포함한 경로를 보고하면 루트 밖 파일 내용이 LLM 프롬프트에 실려 나간다. Anthropic 프로바이더를 쓰는 구성에서는 외부 전송 경로가 된다.

> **증거** — `llm/triage.py:_collect_context`

#### M-3 · Medium — Finding 조회가 1,000건에서 무고지 절단되고 정렬이 알파벳순이다

`list_findings_for_scan` 의 `limit=1000` 이 사실상 하드 캡이다. 초과분은 경고 없이 사라진다 — 진단 도구에서는 커버리지 누락으로 직결된다. 정렬도 `severity.asc()` 인데 severity 가 문자열이라 `HIGH → LOW → MEDIUM` 순으로 나온다.

> **증거** — `db/repo.py:list_findings_for_scan`

#### M-4 · Medium — Alembic 과 `auto_migrate` 가 동시에 스키마 진실을 주장한다

`alembic/versions/` 에 리비전 3개가 있지만, Dockerfile · compose · Makefile 어디에도 `alembic upgrade head` 가 없다. 대신 `app.py` startup 이 `auto_migrate(engine)` 을 호출한다. ARCHITECTURE §3.1 은 정확히 반대로 서술한다("auto_migrate 는 개발 전용 fallback, 프로덕션은 alembic 필수"). 컬럼 추가만 가능한 `auto_migrate` 가 프로덕션 경로에 남아 있으면 스키마 드리프트가 누적된다.

> **증거** — `api/app.py:_startup` · `Dockerfile` / `docker-compose.yml` / `Makefile` 에 alembic 호출 0건

#### M-5 · Medium — 문서화된 설정 중 일부는 코드에서 읽히지 않는다

`db_pool_size` 는 프로파일 3개에 값이 정의되고 ARCHITECTURE §2.4 표에도 실리지만 `init_engine()` 이 사용하지 않는다(`create_engine` 에 전달 안 됨). `custom_resources_dir` 은 선언만 있고 참조 0건. ARCHITECTURE §5.5 의 `OPENSAST_OVERLAY_CONFIG` 는 코드에 존재하지 않는다. 반대로 `scan_service.py` 는 `settings.max_upload_bytes` 대신 하드코딩된 `_MAX_UPLOAD_BYTES` 를 쓴다.

> **증거** — `db/session.py:init_engine` · `custom_resources_dir` / `overlay` grep 결과 · `services/scan_service.py:121`

#### M-6 · Medium — 시간대 표현이 계층마다 다르다

도메인 모델은 `datetime.now(timezone.utc)`(aware), repo 는 `datetime.utcnow()`(naive)를 쓴다. Celery 는 `timezone="Asia/Seoul"`. 같은 스캔의 `started_at` 이 경로에 따라 aware / naive 로 갈리므로 비교 시 `TypeError` 가 나거나 9시간 오차가 조용히 생긴다. 감사 로그 타임스탬프가 증적이 되는 도메인에서는 무시할 수 없다.

> **증거** — `models.py` vs `db/repo.py:mark_scan_running / mark_scan_failed`

#### M-7 · Medium — 커밋 후 큐 발행, 고아 스캔 회수 경로 없음

서비스가 `session.commit()` 직후 `task.delay()` 를 호출한다. 브로커 발행이 실패하면 스캔 행은 `queued` 로 영구히 남고, 이를 회수하는 리퍼(reaper)나 타임아웃이 없다. 아웃박스 패턴 또는 주기적 재큐잉 태스크가 필요하다.

> **증거** — `services/scan_service.py:154-163, 214-219, 248-258`

### 1.3 구조적 관찰 — 버그는 아니지만 비용을 낳는 형태

- **도메인/ORM 이중 모델의 수동 매핑이 3곳에 흩어져 있다.** `repo._finding_from_domain`(도메인→ORM), `tasks.triage_batch_task`(ORM→도메인), `sarif/normalize`(SARIF→도메인). 역방향 변환에서 `raw` 필드가 유실된다. 필드를 하나 추가할 때마다 세 곳을 고쳐야 하고, 지금도 이미 어긋나 있다. 매핑을 `models.py` 옆 한 모듈로 모으면 이 부채가 사라진다.
- **파이프라인이 엔진을 순차 실행한다.** "다중 엔진 오케스트레이터" 인데 `_run_pass` 가 for 루프다. 엔진 간에는 의존성이 없으므로 `ThreadPoolExecutor` 로 감싸는 것만으로 1차 Pass 가 4배 가까이 빨라진다. 문서가 약속하는 "수평 확장" 은 스캔 *사이* 에만 적용되고 스캔 *안* 에는 없다.
- **`report_registry` 가 정의만 되고 배선되지 않았다.** `reports/build_reports()` 는 4개 빌더를 직접 호출한다. 플러그인으로 리포트 포맷을 추가하는 경로가 문서에는 있는데 실행 경로에는 없다.
- **2차 Pass 가 엔진 지정 시 조용히 축소된다.** `options.engines` 를 주면 2차 Pass 는 그 목록과 `SECOND_PASS_ENGINES` 의 교집합만 돈다. `engines=("opengrep",)` 이면 `enable_second_pass=True` 여도 2차 Pass 가 0개다. 경고 로그가 없어 사용자는 심층 분석이 돌았다고 믿는다.

---

## Part 2 — 문서 아키텍처

문서 자체가 시스템이고, 지금 이 시스템에는 두 가지 구조적 결함이 있다 — **진실의 원천이 중복**되고, **시점(as-of)과 상태(as-is)가 구분되지 않는다.**

### 2.1 문서 세트 지도

| 문서 | 규모 | 실제 역할 | 중복 대상 |
|---|---:|---|---|
| `docs/USER_GUIDE.md` | 1,926줄 | 설치+설정+CLI+REST+엔진+룰+LLM+리포트+프론트+DB+테스트+트러블슈팅 | README, CLAUDE.md, ARCHITECTURE §2.4/§4.3 |
| `docs/ROADMAP.md` | 539줄 | Gap 감사 + 버전 로드맵 + 코드 발췌 부록 | 개발계획서 §8, ARCHITECTURE §8, LLM_ENHANCEMENT_PLAN |
| `docs/개발계획서.md` | 498줄 | 제안서 — 배경·법령·엔진 선정·로드맵·KPI·자원 | ARCHITECTURE §1, CLAUDE.md, ROADMAP §4 |
| `docs/ARCHITECTURE.md` | 401줄 | 계층·데이터·보안·확장·배포 설계 | 개발계획서 §3.3, USER_GUIDE §3/§13 |
| `docs/LLM_ENHANCEMENT_PLAN.md` | 230줄 | LLM 전용 Gap + 5단계 계획 | ROADMAP §3.3 및 §4 |
| `CLAUDE.md` | 77줄 | 에이전트용 개요 — 아키텍처·기술스택·49항목 | README, 개발계획서 §9, ARCHITECTURE §1 |

### 2.2 문제 1 — 로드맵이 셋, LLM 계획이 둘

같은 미래를 서로 다른 축으로 세 번 서술한다. 개발계획서 §8 은 **개월**(Phase 1~4), ARCHITECTURE §8 은 **버전**(v0.3.1~v1.0), ROADMAP §4 는 **버전+기간**(v0.4.2~v1.0). 세 축의 매핑이 어디에도 없어서, 지금 무엇을 하고 있는지 문서로 답할 수 없다. LLM 고도화는 ROADMAP §3.3/§4 와 LLM_ENHANCEMENT_PLAN 이 각자의 Phase 번호를 갖는다 — "Phase 2" 가 두 가지를 가리킨다.

### 2.3 문제 2 — Gap 매트릭스가 시점 스냅샷인데 라이브 백로그처럼 읽힌다

ROADMAP §3 의 항목들을 코드에서 직접 확인했다. R1 · R2 만 취소선 + ✅ 로 갱신됐고 나머지는 손대지 않았는데, 실제로는 대부분 해결되어 있다.

| ID | 문서상 상태 | 실측 | 근거 |
|---|---|---|---|
| R3 | 🔴 severity 문자열 비교 버그 | **해결됨** | `merge.py` 가 `_SEVERITY_RANK` 사용 |
| O4 | 🟠 retry/acks_late 없음 | **해결됨** | `tasks.py` 에 3개 태스크 모두 적용 |
| L2 | 🟡 fp_probability 하드코딩 | **해결됨** | `llm_default_fp_probability` |
| L3 | 🟠 triage 캐싱 없음 | ⚠️ 코드는 있으나 배포에서 무효 | H-3 참조 |
| L4 | 🟠 재시도 없음 | **해결됨** | `_complete_with_retry` (tenacity) |
| A1 | 🟠 JWT iat/jti/aud/iss 없음 | **해결됨** | `security.py:create_access_token` |
| A2 | 🟠 refresh token·블랙리스트 없음 | **해결됨** | `create_refresh_token`, `is_blacklisted` |
| A7 | 🟠 CSRF 전무 | **해결됨** | `middleware/csrf.py` |
| C1·C2·C3 | 🔴🟠🟡 root 실행·HEALTHCHECK·single-stage | **전부 해결됨** | Dockerfile 2-stage + `USER opensast` + HEALTHCHECK |
| C7·C8 | 🟠 /metrics·OTel 없음 | **해결됨** | `/metrics`, `observability.py` |
| C10 | 🟡 /ready 정적 응답 | ⚠️ 구현됐으나 상시 실패 | H-1 참조 |
| D1·D2 | 🟠 복합 인덱스 0개·싱글테넌시 | ⚠️ 스키마는 완료, 배선 미완 | 인덱스 6종 + org 컬럼 존재 · C-2 참조 |
| T10·T11 | 🟠 dependabot·lockfile 없음 | **해결됨** | `.github/dependabot.yml`, `requirements*.lock` |
| DOC1·DOC2 | 🟡 CONTRIBUTING·SECURITY 없음 | **해결됨** | 두 파일 모두 존재 |

부록 §7 "검증 노트" 는 더 심하다. 코드 발췌를 **줄 번호와 함께** 인용하는데, 그 코드는 이미 바뀌었다. §7.1 이 인용한 `merge.py:51-56` 의 문자열 비교는 현재 소스에 없다. 문서가 사실이 아닌 것을 사실처럼 증명하고 있다.

> 이 문서에는 이미 **문서 유지 정책** 이 적혀 있다 — "완료 시 완료된 마일스톤 섹션으로 이동". 정책이 없는 게 아니라 지켜지지 않는다. 정책을 강화할 게 아니라, **지킬 필요가 없는 구조** 로 바꿔야 한다.

### 2.4 문제 3 — ARCHITECTURE 가 as-built 과 as-planned 를 섞는다

§4.1 은 "향후: Refresh token" 이라 쓰지만 이미 구현돼 있다. §7 표는 메트릭 · 트레이스를 `(TODO)` 로 표시하지만 둘 다 동작한다. 반대로 §5.5 설정 오버레이는 단정형으로 서술되지만 코드가 없다. 독자가 이 문서를 읽고 "무엇이 존재하는가" 를 알 수 없다 — 아키텍처 문서의 유일한 존재 이유가 무력화된 상태다.

### 2.5 문제 4 — 설정 진실이 세 곳에 있고 이미 어긋났다

| 항목 | ARCHITECTURE | config.py | 실제 사용 |
|---|---|---|---|
| 일반 요청 본문 상한 | 1 MiB (§4.4) | 2 MiB | 2 MiB — 문서 오류 |
| 업로드 상한 | 500 MiB | 500 MiB | 서비스에 별도 하드코딩 |
| `db_pool_size` | 프로파일별 5/10/20 (§2.4) | 동일하게 정의 | **사용되지 않음** |
| `secret_key` 검증 | cloud 에서 기본값 거부 | 경고만 반환 | **프로파일 미활성 → 미실행** |
| `OPENSAST_OVERLAY_CONFIG` | §5.5 에 사용법 명시 | 필드 없음 | **미구현** |

### 2.6 문제 5 — ADR 이 없다

큰 결정들이 산문 속 불릿으로만 남아 있다. 왜 도메인 모델을 ORM 과 분리했는지, 왜 오브젝트 스토어 대신 bind-mount 인지, 왜 passlib 대신 bcrypt 직접 호출인지, 왜 Celery 인지 — 근거 · 대안 · 결과가 기록되지 않았다. 상태(Proposed/Accepted/Superseded)와 날짜가 없으니 결정을 **뒤집을 수도** 없다. KISA CC 트랙에서 설계 근거 추적성은 요구사항이 되기 쉬운 항목이다.

### 2.7 문제 6 — USER_GUIDE 단일 파일 1,926줄

설치 가이드, 설정 레퍼런스, CLI 레퍼런스, REST 레퍼런스, 개발자 문서, 운영 트러블슈팅이 한 파일에 있다. 독자가 여섯 종류인데 진입점이 하나다. 특히 REST 레퍼런스(§5)는 OpenAPI 스키마와 필연적으로 어긋나며, DB 스키마(§14)는 `db/models.py` 와 어긋난다 — 둘 다 생성 가능한 문서를 손으로 쓰고 있다.

### 2.8 사소하지만 고칠 것

- ROADMAP §7 의 제목 줄과 도입 문장이 **두 번 반복**된다(편집 사고).
- ROADMAP §2.1 이 설계 문서를 "각각 500+/1500+ 라인" 이라 적었으나 ARCHITECTURE 는 401줄이다.
- 버전 표기가 네 갈래다 — ROADMAP 제목 `v0.4.1`, 그 헤더 `분석 대상 v0.6.0`, ARCHITECTURE §8 `🚧 v0.4.0`, pyproject · app `0.5.0`.
- README 의 최초 로그인 자격증명이 compose 기본값과 동일한 평문이며, 프로파일이 켜지지 않으므로 변경 강제도 동작하지 않는다.

---

## Part 3 — 아키텍처 결정 기록 (제안)

개별 버그 수정으로 끝나지 않는 네 가지 결정. 이 네 건이 `docs/adr/` 의 첫 항목이 되는 것 자체가 ADR-003 의 실행이다.

### ADR-001: 인가 강제 지점을 서비스 계층에서 라우트 계약으로 끌어올린다

**Status:** Proposed · **Date:** 2026-08-25 · **Deciders:** 백엔드 오너

**Context** — 인가 로직은 `BaseService` 에 잘 설계돼 있으나, 그 로직이 동작하려면 라우트가 `ActorContext` 를 주입해야 한다. 주입은 **선택**이고, 누락 시 기본값이 "무제한" 이다. 이미 8개 라우트가 누락했고 대시보드 5개는 아예 스코핑이 없다(C-2). 개별 라우트를 고치는 것으로는 재발을 막지 못한다.

**Decision** — 서비스가 actor 없이 생성되지 못하게 만든다. `BaseService.__init__` 에서 `actor` 를 필수 인자로 바꾸고, 인증이 없는 컨텍스트(로그인 시도 등)는 `ActorContext.anonymous()` 라는 **명시적** 팩토리로만 만들 수 있게 한다. 동시에 `_org_filter()` 의 기본값을 뒤집는다 — `organization_id is None` 이면 통과가 아니라 `False`(차단)를 반환하고, 전체 조회는 `ActorContext.superadmin()` 에서만 가능하게 한다.

**Options Considered**

| 안 | 복잡도 | 재발 방지 | 평가 |
|---|---|---|---|
| A. 8개 라우트 개별 수정 | 낮음 | 없음 | 즉시 완화되나 다음 라우트에서 재발 |
| **B. actor 필수화 + 기본값 반전 (채택)** | 중간 | 타입 수준 | 컴파일/기동 시점에 누락이 드러남 |
| C. 미들웨어에서 조직 스코핑 강제 | 높음 | 부분적 | ORM 쿼리 가로채기 필요, SQLAlchemy 이벤트 훅 부채 |

**Consequences**
- 쉬워지는 것: 신규 라우트가 인가를 빠뜨리면 즉시 실패한다. 멀티테넌시 스키마(이미 완료)가 실제로 효력을 갖는다.
- 어려워지는 것: 기존 라우트 · 테스트를 한 번에 갱신해야 한다. 배치 · CLI 경로에서 명시적 superadmin 컨텍스트를 만들어야 한다.
- 다시 볼 것: 역할 검사가 라우트 데코레이터(`require_org_access`)와 서비스 내부(`actor.require_role`) 양쪽에 남는다. 어느 쪽을 정본으로 할지 v0.6 이전에 결정한다.

**Action Items**
1. [ ] C-3 · C-4 선차단 — `POST /api/scans` 에 `analyst` 이상 요구 + `source_path` 허용 루트 화이트리스트, SSE 에 인증 의존성 추가 및 세션 수명 분리
2. [ ] `ActorContext.anonymous()` / `.superadmin()` 도입, `BaseService` 시그니처 변경
3. [ ] `_org_filter` 기본값 반전, 라우트 전수 갱신, 대시보드에 조직 필터 적용
4. [ ] 회귀 테스트 — 조직 A 사용자가 조직 B 의 scan/finding/source/dashboard 접근 시 404

### ADR-002: 배포 프로파일을 산출물에서 명시하고 설정 진실을 하나로 만든다

**Status:** Proposed · **Date:** 2026-08-25

**Context** — 프로파일 설계는 훌륭하지만 아무도 켜지 않는다(C-1). 동시에 설정 값이 ARCHITECTURE 표 · `config.py` · 서비스 내부 상수 세 곳에 흩어져 이미 어긋났다(2.5). 두 문제의 뿌리는 같다 — 기본값이 안전한지 검증하는 **단일 지점**이 없다.

**Decision** — `docker-compose.yml` 에 `OPENSAST_PROFILE=docker`, `docker-compose.prod.yml` 에 `cloud` 를 명시한다. `validate_profile()` 이 반환하는 경고를 cloud 프로파일에서는 **기동 실패**로 승격한다(현재는 로그 WARNING 이라 아무도 보지 않는다). 하드코딩된 `_MAX_UPLOAD_BYTES` 를 제거하고, 사용되지 않는 `db_pool_size` 는 `create_engine(pool_size=...)` 에 연결하거나 필드를 삭제한다 — 문서에 있는데 코드에 없는 상태가 최악이다.

**Options Considered**

| 안 | 안전성 | 온보딩 마찰 | 평가 |
|---|---|---|---|
| A. 기본 프로파일을 `docker` 로 변경 | 중간 | 낮음 | 로컬 개발이 불편해지고 근본 원인은 남음 |
| **B. compose 에 명시 + cloud 검증 실패화 (채택)** | 높음 | 낮음 | 산출물이 자기 환경을 선언, 운영은 실패로 알림 |
| C. 프로파일 폐기, 순수 환경변수 | 중간 | 높음 | 안전 기본값 번들이라는 장점을 버림 |

**Consequences**
- 쉬워지는 것: 운영 배포가 약한 시크릿 · 빈 CORS 로는 아예 뜨지 않는다. 문서의 프로파일 표가 처음으로 사실이 된다.
- 어려워지는 것: 기존 cloud 배포가 있다면 시크릿을 갖추기 전까지 기동하지 못한다 — 릴리스 노트에 명시 필요.
- 다시 볼 것: 시크릿을 env 평문으로 두는 문제는 별건. Docker secrets 파일 마운트를 후속 ADR 로.

### ADR-003: 문서를 성격별로 재편하고 ADR 을 도입한다

**Status:** Proposed · **Date:** 2026-08-25

**Context** — 지금 6개 문서가 서로의 일부를 복제하고, 로드맵이 셋이며, Gap 매트릭스는 갱신되지 않아 사실과 반대다. 원인은 게으름이 아니라 **분류 체계의 부재**다. "언제 참인가" 가 다른 세 종류의 글이 한 파일에 섞여 있으면, 갱신 주기가 다르므로 반드시 어긋난다.

**Decision** — 문서를 갱신 주기가 같은 것끼리 묶는다.

| 성격 | 참인 시점 | 위치 | 갱신 계기 |
|---|---|---|---|
| **As-built** — 지금 존재하는 것 | 항상 | `docs/ARCHITECTURE.md` | 동작을 바꾸는 모든 PR |
| **Decision** — 왜 그렇게 했는가 | 결정 시점 고정 | `docs/adr/NNNN-*.md` | 추가만, 수정은 Superseded 로 |
| **Plan** — 하려는 것 | 계획 기준일 | `docs/ROADMAP.md` | 릴리스 |
| **Assessment** — 그때 이랬다 | 감사 시점 고정 | `docs/reviews/YYYY-MM-DD-*.md` | 없음 (동결) |
| **Reference** — 사용법 | 항상 | `docs/guide/*.md` 분할 | 기능 변경 |

핵심은 **Assessment 의 동결**이다. ROADMAP §3 Gap 매트릭스와 §7 부록은 2026-04-16 시점의 감사 결과이므로 `docs/reviews/2026-04-16-gap-audit.md` 로 이동하고 헤더에 "이 문서는 갱신하지 않는다" 를 명시한다. 살아 있어야 하는 미해결 항목만 ROADMAP §4 의 버전 섹션으로 승격한다. 그러면 유지 정책을 지킬 필요 자체가 사라진다.

ARCHITECTURE 는 as-built 만 남긴다 — "향후", "TODO", 버전 로드맵 표(§8)를 전부 걷어내고 ROADMAP 으로 옮긴다. 각 절 끝에 근거 ADR 을 링크한다. USER_GUIDE 는 설치 / 설정 / CLI / REST / 운영 / 트러블슈팅으로 분할하고, REST 레퍼런스는 OpenAPI 에서 생성하며 DB 스키마 절은 삭제하고 `db/models.py` 를 정본으로 가리킨다.

**Options Considered**

| 안 | 유지 비용 | 드리프트 저항 | 평가 |
|---|---|---|---|
| A. 현 구조 유지 + 갱신 규율 강화 | 높음 | 낮음 | 이미 정책이 있는데 지켜지지 않았다 |
| **B. 성격별 재편 + Assessment 동결 (채택)** | 낮음 | 높음 | 동결 문서는 틀릴 수 없다 |
| C. 전부 통합해 단일 문서화 | 중간 | 낮음 | 독자 6종에 진입점 1개 — 지금 문제의 확대 |

**Consequences**
- 쉬워지는 것: "지금 무엇이 있는가" 에 답하는 문서가 하나로 특정된다. 감사 스냅샷은 동결되므로 갱신 의무가 없다.
- 어려워지는 것: 초기 이관 작업(반나절~하루). ADR 작성이 큰 PR 의 새 절차로 추가된다.
- 다시 볼 것: 개발계획서는 제안서라는 성격상 동결 문서다 — `docs/proposal/` 로 옮기고 "2026-04 제안서, 갱신하지 않음" 헤더를 붙인다.

### ADR-004: Triage 를 배치 · 동시 실행으로 전환하고 조용한 실패를 없앤다

**Status:** Proposed · **Date:** 2026-08-25

**Context** — triage 는 Finding 당 LLM 호출 1회를 직렬로 수행하고(H-6), Redis 캐시는 워커 환경변수 누락으로 배포에서 죽어 있으며(H-3), 그 실패는 `except: pass` 로 삼켜진다. 세 문제가 합쳐져 "캐시가 있으니 괜찮다" 는 문서상의 인식과 "매번 전량 재호출 후 타임아웃" 이라는 실제가 갈라졌다.

**Decision** — 세 가지를 함께 바꾼다.
1. 워커 서비스에 `OPENSAST_REDIS_URL` 을 추가하고, Redis 클라이언트를 모듈 수준 커넥션 풀로 승격한다.
2. 캐시 실패를 삼키지 말고 **최초 1회 WARNING** 을 남긴 뒤 그 태스크 동안 캐시를 비활성으로 표시한다 — 조용한 성능 저하보다 시끄러운 저하가 낫다.
3. triage 루프를 `ThreadPoolExecutor`(기본 4~8 동시)로 바꾸고 `llm_max_concurrency`, `triage_max_findings` 설정을 추가한다. 상한 초과분은 severity 순으로 자르되, 잘렸다는 사실을 `ScanResult` 에 기록한다.

**Consequences**
- 쉬워지는 것: Finding 1,000개 규모가 soft time limit 안에 들어온다. 캐시 적중이 실제로 발생해 LLM 비용이 통제된다.
- 어려워지는 것: Ollama 단일 인스턴스에 동시 요청이 몰리면 오히려 느려질 수 있다 — `llm_max_concurrency` 기본값을 프로바이더별로 다르게 잡아야 한다.
- 다시 볼 것: 상한 초과 시 자르는 정책이 행안부 대응에서 허용되는지 확인이 필요하다. 허용되지 않으면 상한 대신 태스크 분할(chunked task)로 가야 한다.

---

## Part 4 — 실행 순서

의존 관계를 반영한 순서다. 1~2번은 다른 작업과 무관하게 지금 나갈 수 있다.

| # | 작업 | 대상 | 규모 |
|---:|---|---|---:|
| 1 | C-3 · C-4 차단 — 스캔 큐잉 역할 검사 + 경로 화이트리스트, SSE 인증 | `routes/scans.py`, `schemas.py` | 반나절 |
| 2 | C-1 프로파일 명시 + H-1 `/ready` import 수정 + H-3 워커 `REDIS_URL` | compose 2종, `app.py:129` | 1시간 |
| 3 | H-2 `is_relative_to()` 교체 (2곳) + H-4 예외 타입 정렬 | `scan_service.py`, `engines/registry.py` | 1시간 |
| 4 | **ADR-001** 인가 경계 — actor 필수화 + 기본값 반전 + 라우트 전수 갱신 | services, routes 전반 | 2~3일 |
| 5 | H-5 저장 멱등성 — `(scan_id, finding_hash)` 유니크 + upsert, 재시도 정책 축소 | `db/repo.py`, alembic, `tasks.py` | 1일 |
| 6 | **ADR-003** 문서 재편 — Assessment 동결, ARCHITECTURE as-built 화, `docs/adr/` 개설 | `docs/` | 1일 |
| 7 | **ADR-004** triage 동시 실행 + 캐시 커넥션 풀 + 실패 로깅 | `llm/triage.py`, `config.py` | 1~2일 |
| 8 | **ADR-002** 설정 정리 — 하드코딩 제거, `db_pool_size` 배선, cloud 검증 실패화 | `config.py`, `db/session.py` | 반나절 |
| 9 | M-1 병합 키에 `rule_id` 포함 · M-3 커서 페이지네이션 · M-6 UTC aware 통일 | `sarif/merge.py`, `db/repo.py` | 1~2일 |
| 10 | 1차 Pass 엔진 동시 실행 · 도메인/ORM 매핑 단일 모듈화 · `report_registry` 배선 | `pipeline.py`, `reports/` | 2~3일 |
