# UPGRADE PLAN — 통합 분석 파이프라인 고도화 계획

- 대상 릴리스: v0.5.0 → v0.6.0 → v1.0.0
- 기준 결정: [ADR-0001 — 2-Pass 분석 파이프라인의 단일 오케스트레이션 통합 (rev.2)](../adr/ADR-0001-unified-analysis-pipeline.md)
- 작성일: 2026-04-23
- 작성자: OpenSAST 아키텍처 팀

## 1. 개요

### 1.1 목표

ADR-0001 에서 결정한 내용을 코드와 운영에 반영한다. 핵심은 네 가지다. 첫째, `ScanPipeline` 에 하드코딩된 Pass 1/Pass 2 구분을 제거하고 모든 엔진을 동등한 `Analyzer` 인터페이스로 통일한다. 둘째, Celery chord 기반 병렬 오케스트레이션과 `light/heavy/llm` 3큐 분리를 도입한다. 셋째, CodeQL(라이선스 리스크)과 ESLint(커버리지 중복) 엔진을 제거하고 Joern(Primary) + Opengrep taint mode(Secondary) 로 심층 분석을 대체한다. 넷째, `findings.sources/confidence/dedup_key` 와 `scan_engine_runs` 테이블을 신설해 머지/중복제거/엔진별 관측을 일원화한다.

### 1.2 범위

코드베이스 실측 결과 본 고도화가 손대는 영역은 다음과 같다. 백엔드는 `opensast/orchestrator/{pipeline.py, tasks.py, celery_app.py}`, `opensast/engines/` 전체, `opensast/sarif/merge.py`, `opensast/services/scan_service.py`, `opensast/db/{models.py, repo.py}`, `opensast/api/routes/scans.py` 를 건드린다. 스키마는 `alembic/versions/` 에 2개 리비전을 추가한다(현재 마지막 리비전은 `20260420_0003_multitenancy.py`). 룰셋은 `rules/codeql/` 를 삭제하고 `rules/joern/` 를 신설한다. 인프라는 `docker-compose.yml`/`docker-compose.prod.yml` 과 `deploy/nginx/` 를 일부 수정한다. 프런트는 `frontend/src/pages/`·`frontend/src/api/`·`frontend/src/store/` 에서 스캔 상세·진행 상태 UI 를 확장한다. CI 는 `.github/workflows/ci.yml` 에 Joern 도커 이미지 빌드·워커 매트릭스를 추가한다.

### 1.3 ADR-0001 와의 대응

ADR 의 §2.1 단일 진입점 → Phase 2. §2.2 병렬·큐 분리 → Phase 2. §2.3 머지·dedup 확장 → Phase 2~3. §2.4 LLM 모드 → Phase 3. §2.5 Celery chord → Phase 2. §2.6 데이터모델 → Phase 1·4. §2.7 엔진 레지스트리 YAML → Phase 1. §2.8 하위호환 → Phase 4. §3 Joern/Opengrep taint → Phase 3.

### 1.4 성공 기준 (KPI)

정량 지표는 네 개를 추적한다. **TTFR(Time To First Result)** — 스캔 큐잉부터 첫 Finding 이 DB 에 UPSERT 될 때까지의 시간. p50 ≤ 5s, p95 ≤ 15s 를 목표(현재는 모든 1차 Pass 엔진이 끝나야 노출되므로 p50 ≈ 30s). **P95 End-to-End** — `fast` 프리셋 90s, `standard` 5min, `deep` 30min(저장소 100kLOC 기준). **중복률** — 같은 위치·CWE 에 대한 분리된 Finding 비율을 현재 대비 70% 이상 감소. **엔진 실패 격리 성공률** — 한 엔진 실패 시 전체 스캔이 degrade 모드로 완결되는 비율 ≥ 99%. 정성 지표로는 MOIS 49개 항목 중 Joern 쿼리로 커버된 항목 수(목표 Phase 3 종료 시 18개 Input Validation 전수 + Deserialization 1개), 그리고 라이선스 리스크 0(CodeQL 바이너리·룰·문서 전면 제거).

## 2. 현황 vs 목표 아키텍처 비교

| 영역 | 현재 (v0.4.x) | 목표 (v1.0) |
|------|---------------|-------------|
| 파이프라인 | `ScanPipeline.scan()` 내부에 `_run_pass("1st")` → `_run_pass("2nd")` 직렬 호출 | `ScanPlanner` 가 실행계획 생성 → `chord(group(engine_tasks), merge_and_triage)` |
| 엔진 목록 | Opengrep / Bandit / ESLint / gosec / SpotBugs / CodeQL | Opengrep / Bandit / gosec / SpotBugs / **Joern** |
| 엔진 인터페이스 | `opensast/engines/base.py::Engine` (run(ScanTarget)→EngineResult) | `Analyzer` 프로토콜 + 메타데이터(`latency_class, criticality, incremental, preset`) |
| 오케스트레이션 | Celery 단일 큐(기본), 태스크는 `run_scan`/`clone_and_scan`/`triage_batch` | 3큐(`light/heavy/llm`) + `engine_task`/`merge_and_triage` + `clone_and_scan` |
| 머지·중복제거 | `sarif/merge.py::merge_findings` (all-at-once, `(file, line, cwe)` 키) | 증분+최종 2단 머지, `DedupKey = (정규화경로, 라인 ±5 블록, CWE, MOIS)` |
| 결과 데이터 | `Finding.engine` 단일 문자열 | `Finding.engine` 대표 + `sources: list`, `confidence: int`, `dedup_key: str` |
| 엔진 실행 기록 | `Scan.engine_stats: JSON`(집계만) | 신규 `scan_engine_runs` 테이블(per-engine 상세) |
| LLM Triage | 스캔 말미 동기 호출(`pipeline.py`) | `deferred/streaming/off` 3모드, `llm` 전용 큐 |
| 진행 이벤트 | 없음(Celery state만) | Redis pub/sub `scan:{id}:progress` + FastAPI SSE/WebSocket |
| 룰셋 | `rules/opengrep/*`, `rules/codeql/java` | `rules/opengrep/*`, `rules/joern/<lang>/<mois_id>.sc` |
| 하위호환 플래그 | `enable_second_pass: bool` | `mode: fast|standard|deep|custom` (플래그는 v1.0 제거) |

## 3. 단계별 로드맵 (Phase 0 ~ Phase 4)

### Phase 0 — 준비 · 프로파일링 · 베이스라인 (2주)

**목표**: 개선 전후 비교를 가능케 하는 벤치마크 하네스와 샘플 코퍼스를 확보하고, 엔진/DB/큐의 현재 성능 프로필을 수치화한다.

**주요 작업**
- `scripts/bench/` 디렉터리 신설. 샘플 저장소 3종(소형 5kLOC Python, 중형 80kLOC Java, 대형 300kLOC 멀티언어)을 Git 서브모듈 또는 `scripts/bench/fixtures.yaml` 로 고정.
- `scripts/bench/run_baseline.py` — 현재 2-Pass 파이프라인을 10회 돌려 p50/p95 스캔시간·엔진별 duration·findings count·중복률을 CSV 로 기록.
- `docs/plan/baseline-metrics.md` 에 측정치 스냅샷 커밋(Phase 4 종료 시 diff 용 reference).
- `tests/fixtures/golden_findings/` 신설 — 기존 엔진이 생성하는 Finding 세트를 회귀 스냅샷으로 저장. 엔진 교체 시 false negative 검증에 사용.

**Deliverables**: 벤치 스크립트, 베이스라인 메트릭 문서, 골든 픽스쳐.

**Definition of Done**: CI 에 `benchmark-nightly` 옵셔널 job 추가, 베이스라인 메트릭 수치가 문서화됨. 팀원 2명 이상이 로컬에서 `make bench-baseline` 재현 확인.

**의존성**: 없음 (선행 단계).

### Phase 1 — Analyzer 추상화 · 레지스트리 · 불필요 엔진 제거 (3주)

**목표**: Pass 1/2 구분을 소스에서 제거하고, 모든 엔진이 동일한 `Analyzer` 프로토콜로 동작하도록 리팩터링. CodeQL·ESLint 엔진을 삭제.

**주요 작업**
- `opensast/engines/base.py` 에 `Analyzer(Protocol)` 도입 — `name`, `languages`, `latency_class`, `criticality`, `incremental`, `run(target)` 노출. 기존 `Engine` 은 같은 파일에서 상속 체인으로 호환.
- `opensast/engines/registry.py` 의 `FIRST_PASS_ENGINES`/`SECOND_PASS_ENGINES` 를 `PRESET_FAST`/`PRESET_STANDARD`/`PRESET_DEEP` 로 개명. `EngineMeta` dataclass 신설.
- `opensast/engines/codeql.py`, `opensast/engines/eslint.py` **삭제**. 레지스트리 내장 dict, `EngineAvailability` 바이너리 매핑, `opensast/config.py::Settings` 의 `codeql_bin`/`eslint_bin` 필드, `tests/test_engine_registry.py`·`test_engine_integration.py` 의 해당 케이스 제거.
- `rules/codeql/` 디렉터리 **삭제** 및 `.gitignore`/`Dockerfile` COPY 구문 정리.
- `docker-compose*.yml` 에서 CodeQL 바이너리 인스톨 스텝 제거(해당되는 경우).
- `opensast/orchestrator/pipeline.py::ScanOptions.enable_second_pass` 를 `mode: Literal["fast","standard","deep","custom"]` 로 변환, 기존 필드는 DeprecationWarning 과 함께 매핑 로직만 남김.
- `opensast/api/schemas.py::ScanCreate`/`GitScanCreate` 에 `mode` 추가, 기존 `enable_second_pass` 는 alias 로 유지.

**Deliverables**: Analyzer 프로토콜 PR, CodeQL/ESLint 완전 제거 PR, 레지스트리 개편 PR.

**Definition of Done**: `grep -r "codeql\|eslint\|FIRST_PASS\|SECOND_PASS" opensast/` 결과가 0건. 기존 128개 pytest 중 삭제된 케이스 외 전부 통과. `opensast list-mois`/`opensast engines` 출력이 새 레지스트리 기반으로 동작.

**의존성**: Phase 0 베이스라인.

### Phase 2 — Celery chord · 큐 분리 · 증분 머지 (4주)

**목표**: 엔진을 Celery group 으로 병렬 실행하고 chord 콜백에서 최종 머지·Triage 를 수행. `light/heavy/llm` 큐 분리. 증분 머지로 TTFR 개선.

**주요 작업**
- `opensast/orchestrator/tasks.py` 리팩터링: `engine_task(scan_id, engine_name, target_path) -> dict` 추가, `run_scan_task` 는 `chord(group([engine_task.s(...) for e in plan]), merge_and_triage.s(scan_id))` 디스패치로 축소.
- `opensast/orchestrator/planner.py` **신설** — `ScanPlanner.plan(target, mode, engines_override) -> ExecutionPlan` 구현.
- `opensast/orchestrator/merge_and_triage.py` **신설** — chord 콜백. 증분 머지는 `engine_task` 종료 직전에, 최종 머지는 콜백 초입에 수행.
- `opensast/orchestrator/celery_app.py` 의 `task_annotations` 확장 — `engine_task.*` 라우팅, `task_routes={"opensast.engine_task.light.*":{"queue":"light"}, "opensast.engine_task.heavy.*":{"queue":"heavy"}, "opensast.triage.*":{"queue":"llm"}}`.
- `opensast/sarif/merge.py` 에 `merge_incremental(scan_id, new_findings)` 추가. `DedupKey` 를 `(file_norm, line_block, tuple(sorted(cwe)), mois_id)` 로 확장. 대표 Finding 선정 규칙에 `Joern > SpotBugs > Opengrep > Bandit/gosec` 반영(CodeQL 엔트리 삭제).
- Redis pub/sub: `opensast/orchestrator/progress.py` 신설. `publish(scan_id, event)` / `subscribe(scan_id)`. 키 네이밍 `opensast:scan:{scan_id}:progress`.
- FastAPI SSE 엔드포인트 추가: `opensast/api/routes/scans.py::stream_progress(scan_id)` → `text/event-stream`. WebSocket 은 Phase 4 로 연기(결정 필요: SSE 만으로 충분한지).
- `docker-compose.yml` 에 `worker-light`, `worker-heavy`, `worker-llm` 서비스 분할. 각 서비스는 동일 이미지를 쓰되 `command: celery -A ... worker -Q light --concurrency=4` 등 큐 지정.
- `tests/test_celery_integration.py` 확장: chord 완결·콜백 호출·증분 머지·부분 공개 이벤트 수신 케이스.

**Deliverables**: Planner 모듈, chord 기반 오케스트레이션 PR, 큐 분리 compose 변경, SSE 엔드포인트.

**Definition of Done**: `fast` 프리셋에서 TTFR p95 ≤ 15s 가 벤치에서 달성됨. 엔진 하나가 인위적으로 실패해도 다른 엔진 결과가 DB 에 반영됨(카오스 테스트 통과). `scan_engine_runs` 테이블에 엔진별 레코드가 정확히 기록됨.

**의존성**: Phase 1 Analyzer 프로토콜.

### Phase 3 — Joern 통합 · Opengrep taint 확장 · LLM 모드 (4주)

**목표**: 심층 엔진을 Joern 으로 치환하고 `deep` 프리셋에만 편입. Opengrep taint mode 룰을 확충해 경량 영역 커버리지를 보강. Triage 를 deferred/streaming/off 3모드로 확장.

**주요 작업**
- `opensast/engines/joern.py` **신설** — `JoernAnalyzer(Analyzer)` 구현. 내부적으로 `joern-parse` → `joern-scan` → JSON/SARIF 출력 파싱. `settings.joern_bin`, `settings.joern_heap_gb` 추가. 타임아웃 기본 1800s, 메모리 oom 가드.
- `opensast/engines/joern/` 하위 헬퍼: `cpg_builder.py`(언어별 프런트엔드 선택), `result_parser.py`(CPG 쿼리 결과 → `Finding`).
- `rules/joern/{java,python,go,javascript,typescript}/` 디렉터리 신설. MOIS ID 별 `.sc` 스크립트와 메타데이터 YAML(`meta.yaml` 에 `mois_id`, `cwe`, `severity`, `description`). 초기 시드는 SR1-1/1-2/1-5/1-6(SQL/XSS/Path Traversal/OS Command) 4건, Phase 3 종료까지 18개 Input Validation + 1개 Deserialization 완료.
- Dockerfile: Joern 설치 스텝 추가 — `RUN curl -L https://github.com/joernio/joern/releases/download/<pinned>/joern-cli.zip -o /tmp/joern.zip && unzip ...`. 이미지 크기 증가 예상 +400MB → multi-stage build 로 `worker-heavy` 이미지에만 포함하도록 분기.
- `docker-compose.yml`: `worker-heavy` 의 `mem_limit: 10g`, `JVM_OPTS: -Xmx8g -XX:+UseG1GC` 적용.
- Opengrep taint mode: `rules/opengrep/{java,python,javascript,go}/taint/` 서브디렉터리 신설, `mode: taint` 룰 추가. `opensast/engines/opengrep.py` 에서 `--taint-experimental` 플래그 여부를 런타임 감지.
- LLM 모드: `opensast/llm/triage.py` 에 `TriageMode = Literal["deferred","streaming","off"]` 도입. `opensast/config.py::Settings.triage_mode` 추가. `streaming` 은 `engine_task` 종료 훅에서 per-finding Triage 태스크를 큐잉.
- `opensast/db/models.py::TriageRecord.input_fingerprint: str` 컬럼 추가(해시 기반 중복 호출 차단).
- `tests/test_engine_integration.py` 에 Joern 케이스 추가(CI 에서 `CI_ENABLE_JOERN=1` 조건부). `tests/test_llm_triage.py` 에 3모드 케이스.

**Deliverables**: Joern 엔진 모듈, 초기 Joern 룰 19건, Opengrep taint 룰 확장, Triage 3모드.

**Definition of Done**: `deep` 프리셋 벤치에서 중형 Java 저장소(80kLOC) 스캔이 p95 ≤ 30min 안에 완결. Joern 실패 시 `fast/standard` 결과만으로 스캔 상태 `done`(degrade) 로 마감. 라이선스 검사(`scripts/check_licenses.py`) 에서 모든 엔진이 허용 라이선스.

**의존성**: Phase 2 오케스트레이션.

### Phase 4 — 데이터 모델 마이그레이션 · 프런트/API 개편 · 레거시 제거 · GA (3주)

**목표**: 스키마 확장을 정식 반영하고, 프런트가 새 필드를 활용해 진행 상태·대표/기여 엔진을 시각화. `enable_second_pass` 플래그 제거. v1.0 GA.

**주요 작업**
- `alembic/versions/20260615_0004_unified_pipeline.py` 작성: `scan_engine_runs` 테이블 생성; `scans` 에 `mode`, `phase`, `progress`; `findings` 에 `sources JSON`, `confidence INT DEFAULT 50`, `dedup_key VARCHAR(128)`; `triage_records` 에 `input_fingerprint VARCHAR(64)`.
- `alembic/versions/20260630_0005_backfill_sources.py` 작성: 온라인 백필 — 기존 `findings` 행을 청크 단위(10k)로 UPDATE 해 `sources = jsonb_build_array(jsonb_build_object('engine', engine, 'rule_id', rule_id, ...))`, `dedup_key = md5(...)` 계산. 중단·재개 가능하도록 `backfill_cursor` 테이블 사용.
- `opensast/db/repo.py::persist_scan_result` 수정: 새 컬럼 영속화, 증분 UPSERT 지원.
- `opensast/api/schemas.py::ScanOut`·`FindingOut` 확장: `mode`, `phase`, `progress`, `engine_runs`, `sources`, `confidence` 노출. `enable_second_pass` 필드는 쓰기 전용으로만 허용, 읽기 응답에서 제거.
- `opensast/api/routes/scans.py` 에 `GET /api/scans/{id}/progress`(SSE, Phase 2 에서 도입한 것 GA 품질로 승격), `GET /api/scans/{id}/engine-runs` 추가.
- 프런트: `frontend/src/pages/ScanDetail.tsx` 에 progress bar, per-engine 카드, 대표/기여 엔진 뱃지. `frontend/src/api/scans.ts` 에 SSE 구독 훅. `frontend/src/store/` 에 scan progress store 추가.
- CLI: `opensast scan --mode {fast|standard|deep}` 플래그 승격. `--no-second-pass` 는 경고 출력 후 `--mode fast` 로 매핑, v1.0 삭제 플래그는 deprecation notice 유지.
- 리포트: SARIF/HTML/Excel 에 `sources`·`confidence` 반영. `opensast/reports/html/` 템플릿에 기여 엔진 표시.
- 문서: `docs/ARCHITECTURE.md`, `README.md`, `docs/USER_GUIDE.md` 의 "2-Pass 분석 파이프라인" 섹션을 "실행 모드 + 엔진 메타데이터" 설명으로 재작성.
- 레거시 삭제: `ScanOptions.enable_second_pass`, `FIRST_PASS_ENGINES`/`SECOND_PASS_ENGINES` 구 심볼 제거.

**Deliverables**: Alembic 리비전 2건, 프런트 개편, 레거시 플래그 제거, GA 릴리스 노트.

**Definition of Done**: 마이그레이션이 스테이징 DB(1M Finding)에서 60분 이내 완료되고 다운타임 ≤ 10분. GA 릴리스 전 `make self-sast` 가 regression 없이 통과. 128개 + 신규 테스트가 모두 green. 사용자 가이드 업데이트 완료.

**의존성**: Phase 1~3 전부.

## 4. 작업분해(WBS) 요약

| Phase | Backend | Infra/DevOps | Engine/Rules | Frontend | QA |
|-------|---------|--------------|--------------|----------|----|
| 0 | bench harness | CI nightly job | golden fixtures 수집 | — | 회귀 스냅샷 baseline |
| 1 | Analyzer 프로토콜, 레지스트리 개편, CodeQL/ESLint 삭제 | Dockerfile 정리 | `rules/codeql/` 삭제 | `mode` 셀렉트 박스 초안 | engine_registry 테스트 개편 |
| 2 | Planner, chord, merge_incremental, SSE | 3-queue compose, worker 분할 | — | progress bar 프로토타입 | chord 카오스 테스트, TTFR 벤치 |
| 3 | Joern 엔진, Triage 3모드 | Joern multi-stage build, heavy 큐 mem_limit | Joern 룰 19건, Opengrep taint 룰 | per-engine 카드 스켈레톤 | Joern 통합 테스트, license check |
| 4 | Alembic 리비전, repo 확장, API 필드 | 마이그레이션 러너, 릴리스 파이프라인 | 문서 재작성 | ScanDetail GA, CLI `--mode` | 스테이징 마이그레이션 리허설 |

## 5. 데이터베이스 마이그레이션 계획

신규 리비전은 두 개로 분리한다. `0004_unified_pipeline` 은 **스키마 변경만** — `scan_engine_runs` 생성, `scans.mode/phase/progress`, `findings.sources/confidence/dedup_key`, `triage_records.input_fingerprint` 컬럼 추가. 기본값을 모두 부여해 기존 행이 즉시 유효하도록 한다(`mode DEFAULT 'standard'`, `phase DEFAULT 'done'`, `progress DEFAULT 100`, `sources DEFAULT '[]'::jsonb`, `confidence DEFAULT 50`). 이 리비전은 온라인 적용 가능하며 잠금 시간은 대형 기관 기준 수십 초 예상(`ALTER TABLE ... ADD COLUMN` + default는 PostgreSQL 11+ 에서 rewrite 생략).

`0005_backfill_sources` 는 **데이터 백필** 전용. `findings` 전체를 10k 단위 청크로 순회하며 `sources = [{engine, rule_id, ...}]`, `dedup_key = md5(file||line||sorted(cwe)||mois_id)` 계산. 진행 커서를 `migration_state` 보조 테이블에 기록해 중단·재개 가능. 백필 동안 서비스는 정상 동작(증분 머지 경로는 새 컬럼을 이미 사용, 조회 경로는 NULL fallback).

하위 호환: `findings.engine` 은 유지되어 구 API·구 리포트와 호환. `enable_second_pass` 플래그는 API 에서 읽기는 불가·쓰기는 가능(internal mapping)으로 1단계 deprecation. v1.0(Phase 4 말) 에 완전 제거.

롤백 전략: `0005` 는 순수 UPDATE 이므로 역방향이 불필요(데이터 유지). `0004` 롤백은 컬럼/테이블 DROP — 다만 프런트/백엔드가 새 필드를 참조하므로 **롤백은 배포 되감기와 동시에만 허용** 한다(결정 필요: `0004` 에 downgrade 를 빈 `pass` 로 둘지 실제 DROP 을 둘지 — 운영 정책으로 확정).

## 6. 엔진 통합 세부

**Joern**. 배포 단위는 공식 릴리스 tarball 을 Dockerfile 에서 pinned 버전(초기 v2.0.x, 결정 필요: 릴리스 평가 후 버전 고정)으로 설치. 이미지 크기가 400~600MB 증가하므로 `worker-heavy` 전용 스테이지로 분리해 `api`/`worker-light` 이미지에는 포함하지 않는다. JVM 기본값은 `-Xmx8g -Xms2g -XX:+UseG1GC -XX:MaxGCPauseMillis=500`. 타임아웃은 엔진 레벨 1800s(설정 오버라이드 가능), Celery `soft_time_limit=1620`. 결과는 Joern SARIF 내보내기로 받아 `opensast/sarif/parser.py` 를 재사용하거나, `joern-export --repr=findings --format=json` 출력을 `result_parser.py` 가 `Finding` 으로 변환. OOM/스크립트 크래시는 비제로 종료코드로 감지해 `scan_engine_runs.status='failed'` 로 마감하고 전체 스캔은 degrade.

**Opengrep taint mode**. 기존 Opengrep 통합(`opensast/engines/opengrep.py`) 은 `--config` 를 여러 개 받도록 이미 설계됨. `rules/opengrep/*/taint/` 를 별도 config 경로로 추가해 동일 엔진 런타임에서 patterns + taint 를 동시에 평가. 룰 예: SR1-1 의 JDBC preparedStatement 우회 경로를 `mode: taint` 로 표현, source 는 `request.getParameter`·sink 는 `Statement.execute*`. 타임아웃과 메모리는 기존과 동일(`light` 큐).

**제거 엔진**. CodeQL 은 `opensast/engines/codeql.py`, `rules/codeql/`, `settings.codeql_bin`, 관련 테스트/문서 블록 전체 삭제. ESLint 는 `opensast/engines/eslint.py`, `settings.eslint_bin`, 관련 테스트 삭제 — Node.js 런타임 의존이 빠지므로 Dockerfile 의 Node 설치 라인 중 `eslint` 전용 부분은 제거(프런트엔드 빌드는 별도 이미지라 영향 없음).

**엔진 버전 거버넌스 (3-Tier 정책 · ADR-0004)**. 엔진별 버전 관리 엄격도는 룰 결합도·CLI 변동성·파이프라인 침투도에 따라 3단계로 차등 적용한다. **Tier 1 (Opengrep, Joern)**: `.env.versions` 에 exact 버전 + SHA256 선언, Renovate 는 patch 만 PR 생성하며 자동 머지 금지, `tests/fixtures/golden/` 기반 회귀 스위트를 CI 게이트로 강제, 전용 ADR 발행. **Tier 2 (SpotBugs)**: 버전 핀 + SHA256 은 동일하게 요구하지만 회귀는 스모크 테스트 수준(기동·기본 detector 몇 개 실행 후 crash 없음 확인), Renovate patch 자동 머지 허용. **Tier 3 (Bandit, gosec)**: major 상한(`>=X,<Y`)만 설정, Renovate patch/minor 자동 머지, 별도 게이트 없이 기존 pytest 수트로 충분. 모든 Tier 공통으로 `vulnerabilityAlerts.enabled=true` 를 통해 CVE 발견 시 즉시 PR 생성하고 24시간 내 긴급 패치 프로세스를 가동한다. 단일 버전 선언 지점(`.env.versions`)과 메타 API(`GET /api/system/engines`)는 Phase 4 산출물로 구현하며, Tier 1 정책은 Phase 3 에서 Joern 으로 먼저 검증한 뒤 Phase 4 초에 Opengrep 에 이식한다. `opensast/engines/base.py::EngineMeta` 에 `license`, `versioning_tier: Literal["strict","moderate","flexible"]`, `upstream_repo` 필드를 도입해 모든 엔진이 자기 정책을 자기기술.

## 7. 오케스트레이션/인프라 변경

**큐 정책**. `light` 큐는 `concurrency=4`, prefetch=4, Celery `worker-light` 서비스에 할당. `heavy` 큐는 `concurrency=1`, prefetch=1, `worker-heavy` 에 할당하고 컨테이너 mem_limit 10g·swappiness=0. `llm` 큐는 `concurrency=2`, Ollama 응답 지연을 고려해 prefetch=1.

**오토스케일**. 단일 노드 compose 환경에서는 오토스케일 없음. Kubernetes(v0.6 이후) 에서는 Celery 큐 길이(Redis `LLEN`)를 KEDA 로 수집해 `worker-light` HPA min=1/max=6, `worker-heavy` min=1/max=2. 결정 필요: `worker-heavy` 를 GPU/CPU 구분할지.

**Redis 네이밍**. pub/sub 채널 `opensast:scan:{scan_id}:progress`. chord 완결 락은 Celery 기본 사용. 멱등 키 `opensast:engine_run:{scan_id}:{engine}` 를 SETNX 로 써서 태스크 재시도 시 중복 실행 방지.

**WebSocket/SSE**. Phase 2 에서 SSE 를 먼저 도입(FastAPI `StreamingResponse`). WebSocket 은 인증·백프레셔 처리가 복잡해 Phase 4 로 연기. 프런트는 `EventSource(/api/scans/{id}/progress)` 로 연결.

**Docker/Helm**. `docker-compose.yml` 의 단일 `worker` 를 `worker-light`/`worker-heavy`/`worker-llm` 으로 분리. `docker-compose.prod.yml` 에는 메모리·재시작 정책 오버라이드. Helm chart(v0.6 대응) 는 별도 repo 로 분리 예정 — 결정 필요.

## 8. 품질·테스트 전략

**단위 테스트**: Planner(프리셋 → 엔진집합 매핑), DedupKey 해싱, merge_incremental 의 순서 불변성(엔진 A→B 와 B→A 결과 동일), Triage 3모드 상태기계.

**통합 테스트**: `tests/test_celery_integration.py` 에 chord 완결·엔진 실패 격리·증분 이벤트·SSE 수신 케이스 추가. Joern 은 `CI_ENABLE_JOERN=1` 가드(이미지 빌드 시간 이슈).

**회귀 테스트**: Phase 0 의 골든 픽스쳐를 Phase 1~3 각 단계에서 재실행, 기존 Finding 대비 **추가는 허용, 손실은 금지**(단 CodeQL/ESLint 전용 Finding 은 예외 목록으로 관리). 손실이 감지되면 Joern/Opengrep 룰 보강으로 메움.

**성능 벤치**: `scripts/bench/run_pipeline.py` 를 Phase 0~4 모든 단계에서 실행, TTFR p50/p95·E2E p50/p95·중복률·FP율(골든셋 기준) CSV 를 `docs/plan/metrics-trail.csv` 에 축적.

**FP/FN 데이터셋**: `tests/fixtures/mois_corpus/` 에 MOIS 49개 항목별 positive 1개·negative 1개 샘플. Phase 3 종료 시 FP율 ≤ 15%, FN율 ≤ 10% 목표(현재 수치는 Phase 0 에 확정).

**감사 증빙**: `audit_logs` 에 `scan.mode`, `engine_run.start/finish`, `triage.mode` 를 기록. 감리 요청 시 `opensast report --audit-trail` 로 SHA256 해시 포함 감사 패키지 생성.

## 9. 리스크 & 완화

| 리스크 | 영향 | 확률 | 완화 |
|--------|------|------|------|
| Joern 메모리 폭증으로 worker OOM | 스캔 실패, 호스트 불안정 | 중 | `heavy` 큐 격리, mem_limit 10g, `-Xmx8g`, OOM 감지 시 자동 degrade |
| 증분+최종 머지 순서 불일치로 대표 Finding 이 플리핑 | UI 혼란, 감사 신뢰도↓ | 중 | `DedupKey` 결정적 해싱 + `representative_engine` 고정 규칙(priority 동률이면 엔진 이름 사전순) |
| Alembic 백필 중 DB 부하 | 프로덕션 지연 | 중 | 청크 10k + 배치 간 sleep 200ms, off-peak 스케줄 |
| Joern 쿼리 생태계 빈약 → MOIS 커버리지 공백 | FN↑ | 고 | Phase 3 스프린트 중 MOIS ID 별 시드 19건 필수. 공백은 Opengrep taint 로 보완 |
| SSE 프록시 호환성(nginx buffering) | 진행 이벤트 지연 | 낮 | `deploy/nginx/` 에 `proxy_buffering off; proxy_read_timeout 24h` 추가 |
| `enable_second_pass` 클라이언트 호환 | 기존 CLI/CI 파이프라인 깨짐 | 중 | Phase 1~3 alias 유지, v1.0 전 2개 마이너 릴리스에서 deprecation warning |
| 라이선스 재검증 누락 | 공공 납품 거버넌스 리스크 | 낮 | `scripts/check_licenses.py` CI 필수, Joern 버전 고정 시 매번 재검증 |
| Celery chord 실패 시 결과 소실 | 스캔 영구 실패 | 낮 | chord 타임아웃 시 `merge_and_triage` 를 별도 복구 태스크로 스케줄 |

## 10. 마이그레이션/배포 전략

**Feature flag**. `OPENSAST_PIPELINE_V2=true|false` 환경변수로 Phase 2 결과를 토글. false 이면 기존 직렬 `_run_pass` 경로. Phase 2 머지 즉시 기본값 true, Phase 3 말에 플래그 제거.

**카나리**. 다중 테넌시 환경(v0.3.2 의 organizations)에서 선택 조직만 새 파이프라인으로 라우팅 — `organizations.pipeline_version` 컬럼(결정 필요: 신설할지 환경변수로 대체할지). 1주 관찰 후 전체 전환.

**Degrade 모드**. Joern 태스크가 실패/타임아웃이면 `scan_engine_runs.status='failed'`, `scan.phase='done'`(대신 `warnings:['joern_unavailable']` 메타). 결과는 `fast`/`standard` 엔진 것만 포함, UI 는 배너로 공지. 사용자는 `opensast scan --retry-deep <scan_id>` 로 Joern 만 재실행 가능(Phase 4).

**롤백 기준**. Phase 2/3 배포 후 24시간 안에 다음 중 하나 발생 시 즉시 롤백: TTFR p95 가 베이스라인 대비 2x 이상, 스캔 실패율 5% 초과, DB CPU 80% 초과 지속 10분, 라이선스 위반 경고. 롤백은 feature flag 로 1차, 배포 되감기로 2차.

## 11. 체크리스트 & 마일스톤 (T = 킥오프 주차)

- **T+0 ~ T+2**: Phase 0 — 벤치 하네스, 골든 픽스쳐, 베이스라인 메트릭 커밋.
- **T+2 ~ T+5**: Phase 1 — Analyzer 프로토콜, CodeQL/ESLint 제거, `mode` 파라미터. v0.5.0-rc1 태그.
- **T+5 ~ T+9**: Phase 2 — chord/큐 분리/증분 머지/SSE. v0.5.0-rc2.
- **T+9 ~ T+13**: Phase 3 — Joern 통합, Opengrep taint 확장, Triage 3모드. v0.5.0 GA.
- **T+13 ~ T+16**: Phase 4 — Alembic 리비전, 프런트 개편, 레거시 플래그 제거. v0.6.0 카나리 → v1.0.0 GA.

총 소요 16주(약 4개월) 가이드. 각 Phase 말 금요일에 팀 리뷰와 KPI 보고.

### 결정 사항 이력 (2026-04-24 확정)

원래 6개 "결정 필요" 태그였던 항목은 모두 [ROADMAP §8](../ROADMAP.md#8-adr-0001-결정-필요-항목-확정-내역) 에 최종 결정이 기록되었다. 요약:

1. **SSE 전용 채택, WebSocket 도입 폐기** — 진행 이벤트는 단방향 push. 양방향 use case 발생 시 별도 ADR.
2. **Alembic `0004` downgrade 는 가드된 DROP** — `ALEMBIC_FORCE_DOWNGRADE=1` 환경변수 필수.
3. **CPU 전용 `worker-heavy` + GPU 분리된 `worker-llm`** — 자원 프로파일·실패 모드 격리.
4. **카나리 라우팅은 Redis 키(`opensast:pipeline_v2:org_ids` SET)** — 영구 컬럼 오염 방지, Admin API 로 즉시 SADD/SREM.
5. **Joern 버전은 Phase 3 T+9 에 v2.0.x 최신 stable 스냅샷 (ADR-0002)** — Renovate 월간 patch + 골든 회귀 강제.
5b. **엔진 버전 거버넌스 3-Tier 정책 (ADR-0004 신설)** — Tier 1: Opengrep/Joern 엄격, Tier 2: SpotBugs 중간, Tier 3: Bandit/gosec 유연.
6. **Helm chart 는 v1.0 GA 까지 in-tree (`deploy/helm/`)**, 이후 생태계 확산 시 `opensast-helm` 리포 분리 검토.

상세 사유와 구현 가이드는 ROADMAP §8 과 각 ADR 문서 참조.
