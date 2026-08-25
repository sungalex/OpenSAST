# ADR-0001: 2-Pass 분석 파이프라인의 단일 오케스트레이션 통합

- 상태(Status): **Proposed (rev.2)** — 합의 이후 v0.5.0 마일스톤에서 단계적 도입
- 작성일: 2026-04-23
- 작성자: OpenSAST 아키텍처 팀
- 관련 문서: `docs/ARCHITECTURE.md`, `CLAUDE.md`, `opensast/orchestrator/pipeline.py`, `opensast/sarif/merge.py`, `opensast/orchestrator/tasks.py`

### 변경 이력

- v1 (2026-04-23): 초안. 2-Pass 모델 통합, Celery chord + Redis pub/sub 기반 단일 오케스트레이션 제안.
- v2 (2026-04-23): CodeQL 제거(비상업 소스 이용 라이선스 이슈), ESLint 제거(JS/TS 는 Opengrep 룰로 커버). CodeQL 대체로 **Joern(Primary) + Opengrep taint mode(Secondary)** 도입. 엔진 목록·다이어그램·큐 배정·레지스트리 예시 전면 교체.

## 1. 맥락 (Context)

OpenSAST 는 행정안전부 「SW 보안약점 진단가이드」 49개 항목을 다중 엔진 오케스트레이션으로 점검하는 오픈소스 SAST 도구다. 초창기 구조는 명시적인 2-Pass 모델이었다. 1차 Pass 는 Opengrep·Bandit·gosec 같은 경량 패턴매칭 엔진을 직렬 실행해 약 30초 내에 결과를 돌려주고, 2차 Pass 는 심층 데이터플로우 엔진을 별도의 스케줄 기반 경로로 실행한 뒤 결과를 덧붙였다. 이후 3단계로 LLM Triager 가 전체 Finding 을 순회하며 오탐확률과 조치안을 `triage` 필드에 기록한다.

이 구조는 초기 설계 목표(“빠른 피드백 + 지연 허용 심층 분석”)에는 부합했지만, 운영 측면에서 마찰이 누적되었다. `ScanPipeline.scan()` 내부에 Pass 구분이 하드코딩되어 있어 엔진 추가·제거가 어렵고, 결과 병합은 모든 엔진이 끝난 뒤 한 번에만 일어나며, DB 의 `Finding.engine` 은 단일 값이라 여러 엔진이 같은 취약점을 확증한 사실이 머지 단계에서 버려진다. 사용자는 Pass 1·2 를 개념적으로 합쳐 **단일 진입점 · 통합 스케줄링 · 일원화된 머지/중복제거** 로 재설계하길 원한다. 본 ADR 은 이 방향을 구체화한다.

또한 본 개정(v2)은 엔진 구성 자체를 손본다. **CodeQL** 은 GitHub 의 라이선스 정책상 "공개 비상업 오픈소스 프로젝트에 한해 무료" 라는 제약이 있어, 공공기관·감리업체 상업 배포 시나리오를 핵심 타깃으로 삼는 OpenSAST 에는 부적합하다. **ESLint** 는 JS/TS 범위에서 Opengrep 의 커스텀 룰과 기능이 상당 부분 겹쳐, 엔진 유지 비용 대비 차별화가 약하다고 판단해 제외한다. JS/TS 보안 진단은 `rules/opengrep/javascript` 로 일원화한다.

## 2. 결정 (Decision)

**Pass 1 / Pass 2 구분을 소스 레벨에서 제거하고, 모든 엔진을 동등한 "플러그가능 분석자(analyzer)" 로 추상화한 단일 오케스트레이션 파이프라인을 도입한다.** 빠른 피드백 특성은 Pass 구분이 아니라 엔진 메타데이터(예상 지연, 우선순위, 결과 스트리밍 여부)와 스케줄러의 정책으로 표현한다. 기존 "빠른 스캔" UX 는 실행 모드 프리셋(`mode=fast`)으로 하위 호환한다.

CodeQL 을 대체할 다국어 심층 데이터플로우 엔진으로는 **Joern 을 Primary** 로, Opengrep taint mode 를 보조 커버리지 확장 수단으로 채택한다(상세는 §3). SpotBugs + FindSecBugs 는 Java 전용 시맨틱 분석기로 유지한다.

### 2.1 단일 진입점과 실행 플로우

분석 요청은 어떤 경로로 들어오든 — REST(`POST /api/scans`), CLI(`opensast scan`), VS Code 확장, 웹훅 — 다음 동일한 플로우로 수렴한다.

```
요청  →  ScanPlanner           : 대상 언어/프로파일/모드로 실행 계획 생성
      →  ScanCoordinator       : Scan row insert, 엔진별 EngineRun row 생성
      →  Celery chord           :
             ├─ engine_task(opengrep)            ┐
             ├─ engine_task(bandit)              │
             ├─ engine_task(gosec)               │ group — 병렬 실행
             ├─ engine_task(spotbugs)            │
             └─ engine_task(joern)               ┘
             └─ callback: merge_and_triage
      →  (각 engine_task 종료 시 partial merge + 이벤트 push)
      →  merge_and_triage       : 최종 중복제거 + LLM Triage + 게이트 평가
      →  post_scan 훅 / 리포트 생성 트리거
```

`ScanPlanner` 는 저장소 언어 힌트, 사용자 프리셋(`fast | standard | deep | custom`), 엔진 가용성(`available_engines()`)을 조합해 실제 돌릴 엔진 집합과 각 엔진의 타임아웃·우선순위·필수/선택 여부를 결정한다. 예컨대 `fast` 는 Opengrep·Bandit·gosec 만 포함해 기존 1차 Pass 와 동일한 지연을 보장하고, `standard` 는 여기에 SpotBugs 를 더하며, `deep` 은 Joern 까지 포함해 인터프로시저 테인트 분석을 수행한다.

### 2.2 엔진 실행 전략: 병렬·우선순위·조기결과

모든 엔진은 **기본적으로 병렬**로 실행한다. 현행 직렬 `_run_pass` 루프는 빠른 엔진이 느린 엔진 뒤에서 기다리는 낭비를 일으키므로 Celery `group` 으로 대체한다. 워커 큐는 세 단계로 분리한다. **`light`** 큐는 Opengrep·Bandit·gosec 같은 수초~수십초 엔진이 쓰고, **`heavy`** 큐는 SpotBugs 와 Joern 전용 — JVM 기반으로 메모리 수 GB 를 점유하는 엔진을 격리해 경량 엔진과 자원 경쟁을 막는다. **`llm`** 큐는 Triage 용이다. Joern 워커는 `concurrency=1`, 기본 힙 `-Xmx8g` 를 권장 설정으로 문서화한다.

각 엔진 태스크는 세 가지 메타데이터를 갖는다. **expected_latency_class** (instant <5s, fast <60s, slow <15min, deep <2h), **criticality** (required / optional), **incremental** 지원 여부. Joern 은 `deep · optional · non-incremental`, Opengrep 은 `fast · required · incremental` 로 분류된다. optional 엔진이 타임아웃 나도 전체 스캔은 성공으로 완결되며 `engine_runs` 에 상태만 남긴다.

빠른 피드백과 완전한 결과의 트레이드오프는 **"조기 부분 공개(early partial disclosure)"** 로 해결한다. 엔진 하나가 끝날 때마다 (i) 자신의 Finding 을 UPSERT 하고 (ii) 동일 `scan_id` 의 기존 결과와 부분 머지한 뒤 (iii) `scan.phase=partial, completed_engines=...` 로 상태를 갱신해 WebSocket 이벤트를 쏜다. 30초 안에 Opengrep/Bandit/gosec 결과가 도착하면 사실상 기존 1차 Pass 와 동일한 체감을 준다. Joern 이 15분 뒤에 끝나면 그 시점에 Finding 이 추가되거나, 같은 위치의 기존 항목의 신뢰도가 상향될 뿐이다.

### 2.3 결과 머지·중복제거 일원화

머지/중복제거는 두 단계다. **증분 머지**는 엔진 종료 시 해당 엔진의 신규 Finding 만 기존 세트와 비교하고, **최종 머지**는 모든 required 엔진 종료 후 chord 콜백에서 한 번 더 수행해 경계 사례를 보정한다. 양쪽 모두 동일한 `DedupKey` 를 쓴다.

`DedupKey` 는 **정규화된 파일 경로 + 라인 범위 블록(±5줄 윈도) + CWE 집합 + MOIS ID** 로 확장한다. 라인 윈도는 엔진마다 보고 위치가 1~3줄씩 어긋나는 문제를 흡수한다. 대표 Finding 선정 우선순위는 `Joern > SpotBugs > Opengrep > Bandit/gosec` 로 갱신한다(인터프로시저 정밀도 기준). 나머지 기여는 `Finding.sources: list[EngineContribution]` 에 누적해 교차검증 사실과 신뢰도 계산에 반영한다. 단일 엔진이면 `confidence = engine_priority`, 2개 이상이 같은 위치를 확증하면 `confidence += Σ(contrib_priority) * 0.3` (상한 100).

### 2.4 LLM 후처리의 통합 위치

LLM Triage 는 별개 "3단계" 가 아니라 **엔진 파이프라인의 맨 끝에 붙는 또 하나의 post-merge 태스크**다. `deferred`(기본, chord 콜백 배치) · `streaming`(증분 머지마다 개별 Triage 큐잉) · `off`(감리·감사 상황에서 LLM 개입 금지) 세 모드를 제공한다. 어느 모드든 Triage 는 `Finding` 을 수정하지 않고 `TriageRecord` 만 삽입·갱신한다 — 원본 탐지 증적 보존은 행안부 진단가이드 준수상 비타협 원칙이다.

### 2.5 비동기 처리 모델 변경점

기존 `run_scan_task` 는 **오케스트레이션 태스크**로 역할이 좁혀지고, 실제 엔진 실행은 `engine_task(scan_id, engine_name)` 로 분리된다. 오케스트레이션 태스크는 `chord(group(engine_tasks), merge_and_triage.s(scan_id))` 를 디스패치한 뒤 즉시 리턴한다. 부분 진행 상태 푸시는 Redis pub/sub 채널(`scan:{scan_id}:progress`) 을 통해 FastAPI WebSocket/SSE 로 중계된다. `clone_and_scan_task` 는 clone 단계만 담당하고 오케스트레이션 태스크를 체이닝한다.

### 2.6 데이터 모델 변경점

- `scans` 테이블에 `mode`(fast/standard/deep/custom), `phase`(queued/running/partial/merging/triaging/done/failed), `progress`(0–100) 추가.
- 신규 테이블 `scan_engine_runs(scan_id, engine, status, started_at, finished_at, duration_ms, findings_count, error, queue)` — 엔진별 진행·성공·실패·생략을 영속화해 Pass 1/2 구분을 대체.
- `findings` 에 `sources: JSON`, `confidence: int`, `dedup_key: str` 추가. `engine` 은 "대표 엔진" 으로 의미를 좁힘. `finding_hash` 는 호환 유지.
- `triage_records` 에 `input_fingerprint` 추가 — 동일 입력에 대한 중복 LLM 호출 차단.
- 기존 데이터는 `sources = [{engine: <legacy>}]` 로 백필.

### 2.7 엔진 레지스트리 예시

YAML 로 표현하면 다음과 같다.

```yaml
engines:
  opengrep:
    preset: [fast, standard, deep]
    queue: light
    latency: fast
    criticality: required
    incremental: true
  bandit:
    preset: [fast, standard, deep]
    queue: light
    latency: fast
    criticality: optional
    languages: [python]
  gosec:
    preset: [fast, standard, deep]
    queue: light
    latency: fast
    criticality: optional
    languages: [go]
  spotbugs:
    preset: [standard, deep]
    queue: heavy
    latency: slow
    criticality: optional
    languages: [java, kotlin]
  joern:
    preset: [deep]
    queue: heavy
    latency: deep
    criticality: optional
    languages: [java, python, go, javascript, typescript]
    jvm_heap: 8g
```

### 2.8 하위 호환성

`POST /api/scans` 의 `enable_second_pass: bool` 은 당분간 유지하되 `mode` 로 매핑한다(`true → standard`, `false → fast`). `opensast scan --no-second-pass` 동일. v1.0 에서 플래그를 제거하고 `--mode` 로 일원화한다.

## 3. CodeQL 대체 엔진 검토 (Alternatives for Deep Semantic Analysis)

CodeQL 이 수행하던 "다국어 인터프로시저 테인트·데이터플로우 분석" 역할을 메울 오픈소스 후보를 다음 기준으로 평가했다: **라이선스(상업·공공 배포 가능)**, **지원 언어(Java/Python/Go/JS/TS 우선)**, **테인트 깊이**, **운영 비용**, **MOIS 49개 중 시맨틱 의존 카테고리(Input Validation 18개, Deserialization, 인증·인가, 정보노출) 커버리지**.

**Joern** — Apache-2.0. CPG(Code Property Graph; AST + CFG + PDG 통합) 기반으로 Scala/CPGQL 질의 언어를 제공. Java·Python·JavaScript·TypeScript·Go·C/C++ 등 다언어 프런트엔드가 공식 유지되며, 인터프로시저 테인트가 기본 내장이라 CodeQL 의 `TaintTracking` 쿼리와 개념적으로 가장 가깝다. 운영 비용은 JVM 기반으로 메모리 수 GB~수십 GB, 중~대형 저장소에서 수 분~수십 분이 현실적이다. MOIS Input Validation(SR1-x), Deserialization(CE-5), 권한·인가(SF-x) 계열 모두 CPG 질의로 표현 가능하다.

**Opengrep taint mode** — Opengrep(LGPL-2.1) 은 Semgrep CE 의 커뮤니티 계승 포크로, intra-procedural taint 와 파일 간(interfile) 분석의 일부를 제공한다. 완전한 인터프로시저 테인트는 제한적이지만, Input Validation 류 **국소적 데이터플로우**(예: HTTP 파라미터 → JDBC preparedStatement 인자) 는 충분히 커버한다. 실행 비용이 매우 낮고 이미 `light` 큐로 돌고 있어 추가 운영 부담이 없다.

**Facebook Infer** — MIT. Bi-abduction 기반으로 Java/C/C++ 에서 null deref · 리소스 누수 · 동시성 결함에 강하지만, 보안 테인트 중심 엔진이 아니며 Python/Go 미지원. MOIS "코드오류" 범주(7개)에는 매력적이지만 Input Validation 주류 커버리지에는 부족.

**Pysa(Pyre)** — MIT. Python 전용 인터프로시저 테인트. Python 파이프라인에는 매우 강력하나 단일 언어라 "다국어 CodeQL 대체" 라는 본 목적에는 단독 채택이 어렵다.

**SonarQube CE** — LGPL-3. Community Edition 은 보안 테인트·DBD 룰을 포함하지 않는다(Developer Edition+ 상업 라이선스 전용). "공공 배포 가능한 오픈소스" 조건을 실질적으로 만족하지 못함.

**권고안 — Joern(Primary) + Opengrep taint mode(Secondary).** Joern 은 Apache-2.0 으로 공공·상업 배포가 자유롭고, Java·Python·Go·JS/TS 를 하나의 엔진으로 커버해 CodeQL 의 다국어 성격을 그대로 계승한다. 다만 설치 난이도와 운영 비용이 있으므로 `deep` 프리셋에만 편입해 기본 UX 에 영향을 주지 않는다. 경량 영역의 테인트 커버리지는 Opengrep taint mode 룰을 확충해 메운다 — 두 엔진은 상호보완적이며, Opengrep 이 Joern 의 워밍업 전에 대부분의 Input Validation 케이스를 이미 보고하는 구조가 된다. Python 전용 심층 분석이 필요한 기관은 선택적으로 `pysa` 플러그인을 붙일 수 있도록 엔진 레지스트리에 자리만 열어둔다.

## 4. 고려한 오케스트레이션 대안 (Orchestration Alternatives)

**A — 현행 유지 + 부분 개선.** 2-Pass 구분은 둔 채 1차 Pass 에 병렬화만 도입. 구현은 쉬우나 Pass 경계에 묶인 경직성과 단일 `engine` 컬럼 문제는 그대로 남는다.

**B — 엔진을 마이크로서비스로 완전 격리.** gRPC 스트리밍 기반. 확장성은 뛰어나지만 로컬/온프레미스 설치 경험이 나빠지고 운영 복잡도가 급증 — 현 설치 페르소나(행안부 산하기관·감리업체)에는 과설계.

**C — Kafka/NATS 이벤트 버스.** 이벤트 기반 확장에는 이상적이나 Celery + Redis 스택 재구성 비용이 크다. 채택안의 chord + pub/sub 이 유사한 이점을 스택 보존 상태로 제공한다.

선정안은 **통합 오케스트레이션 + Celery chord + Redis pub/sub**, **엔진 구성은 Opengrep · Bandit · gosec · SpotBugs · Joern** 이다.

## 5. 트레이드오프와 위험 (Consequences)

**긍정.** Pass 경계 제거로 엔진 추가·제거가 단순해지고, 병렬화로 평균 스캔 소요가 단축된다. 부분 공개 UX 가 기존 Pass 1 의 체감 속도를 보존하며, `sources`/`confidence` 도입으로 머지 품질과 보고서 설명력이 개선된다. 엔진 측면에서는 CodeQL 제거로 **라이선스 리스크가 완전히 사라지고**, Joern 도입으로 Apache-2.0 아래 동일 수준의 인터프로시저 테인트 분석 능력을 확보한다. ESLint 제거로 엔진 가짓수가 줄어 유지보수 표면이 작아진다.

**부정 및 리스크.** Joern 은 CodeQL 대비 쿼리 생태계가 작아 MOIS 49개 각 항목에 대응하는 쿼리를 **자체적으로 작성·유지해야 하는 부담**이 생긴다. 이를 위해 `rules/joern/<언어>/<mois_id>.sc` 디렉터리 구조를 신설하고, 커뮤니티 쿼리(Joern-Repo의 `query-database`) 를 벤더링해 출발점을 확보한다. 또 Joern 은 JVM 기반으로 메모리 부담이 커 `heavy` 큐 격리와 워커당 `concurrency=1` 를 필수화한다. Opengrep taint mode 는 인터프로시저가 불완전하므로 커버리지 공백을 명시적으로 문서화하고, 해당 공백은 Joern 쿼리로 메운다. SQLite(로컬 프로파일)의 동시성 한계로 증분 머지는 Docker/Cloud 프로파일에서만 활성화하고 로컬은 최종 머지 폴백을 기본값으로 둔다.

## 6. 마이그레이션 계획 (Migration)

1단계(Schema & shim): `scan_engine_runs`, `findings.sources/confidence/dedup_key`, `scans.mode/phase/progress` Alembic 리비전 적용. 기존 파이프라인에 관측 훅만 추가.
2단계(Planner & parallelization): `ScanPlanner` 도입, Celery `group` 병렬화. `FIRST_PASS_ENGINES`/`SECOND_PASS_ENGINES` 상수는 `PRESET_FAST`/`PRESET_STANDARD`/`PRESET_DEEP` 로 개명. **CodeQL·ESLint 엔진 클래스 및 바이너리 의존 삭제.**
3단계(Engine swap): **Joern 엔진 추가**(`opensast/engines/joern.py`), Opengrep taint 룰 확충, `rules/joern/` 디렉터리 신설과 MOIS ID 매핑 시드.
4단계(Chord & partial): 오케스트레이션을 chord 로 재구성, Redis pub/sub 진행 이벤트, UI 부분 상태 표시.
5단계(LLM mode): Triage 를 deferred/streaming/off 모드 선택 가능하게.
6단계(Cleanup): `enable_second_pass` 를 경고화하고 v1.0 에서 제거. `ARCHITECTURE.md`/`README.md`/`USER_GUIDE.md` 의 2-Pass 설명을 "실행 모드 + 엔진 메타데이터" 관점으로 재작성.

## 7. 결론

본 ADR 은 Pass 1/2 라는 시간축 분할을 없애고 엔진 메타데이터·스케줄러 정책으로 "빠른 피드백" 과 "깊은 분석" 을 동시에 표현하는 단일 오케스트레이션으로 이행할 것을 제안한다. 동시에 라이선스 리스크가 있는 CodeQL 과 차별화가 약한 ESLint 를 제거하고, **Joern 을 다국어 심층 분석의 축**으로 삼으며 Opengrep taint mode 로 경량 영역의 테인트 커버리지를 보강한다. 사용자 가시적 UX 는 퇴보하지 않으며(부분 공개로 체감 속도는 개선), 엔진 생태계 확장·결과 품질·라이선스 건전성·운영 관측성 측면에서 이득이 명확하다. 채택 시 v0.5.0 에서 1~4단계, v0.6.0 에서 5단계, v1.0.0 에서 6단계 정리를 완료하는 로드맵을 권장한다.
