# Local LLM (Ollama/Gemma) 고도화 계획

> **문서 기준일**: 2026-04-20
> **대상 버전**: v0.6.0 → v0.9.0
> **문서 목적**: 로컬 LLM 오탐 필터링 파이프라인의 현 구현을 진단하고, 운영·정확도·관측성·공공부문 특화 측면의 고도화 경로를 단계별 PR 단위로 제시한다.
> **연관 문서**: [ROADMAP.md](./ROADMAP.md) v0.7.0·v1.0.0 트랙과 정합.

---

## 목차

1. [한 줄 요약](#1-한-줄-요약)
2. [현황 진단](#2-현황-진단)
3. [Gap 매트릭스](#3-gap-매트릭스)
4. [단계별 고도화 로드맵](#4-단계별-고도화-로드맵)
   - [Phase 1 — Quick Wins (1주)](#phase-1--quick-wins-1주)
   - [Phase 2 — 정확도 & 프롬프트 체계화 (2~3주)](#phase-2--정확도--프롬프트-체계화-23주)
   - [Phase 3 — 성능·확장성 (3~4주)](#phase-3--성능확장성-34주)
   - [Phase 4 — 관측성·거버넌스 (2주)](#phase-4--관측성거버넌스-2주)
   - [Phase 5 — 공공부문 특화 (2~3주)](#phase-5--공공부문-특화-23주)
5. [KPI 및 검증 방법](#5-kpi-및-검증-방법)
6. [리스크 및 완화](#6-리스크-및-완화)
7. [부록 — 구현 참조 위치](#7-부록--구현-참조-위치)

---

## 1. 한 줄 요약

> **"오탐 필터링의 핵심 기능은 완성되었다. 다음은 MOIS 49개 항목별 프롬프트 분기 → 배치/병렬 호출 → 관측성 → 에어갭(망분리) 강제 모드 순서로 고도화하면 KISA CC 인증 트랙과 공공기관 운영요건을 동시에 충족할 수 있다."**

현 파이프라인(`opensast/llm/`)은 **원본 Finding 절대 보존 원칙**, 3-프로바이더 폴백(ollama→anthropic→noop), tenacity 재시도, Redis 24h 캐시, 한국어 MOIS 프롬프트를 이미 갖추고 있다. 그러나 **(1) 단일 프롬프트 템플릿의 범용성 한계**, **(2) 순차 호출로 인한 대형 PR 지연**, **(3) Ollama 측 토큰/latency 메트릭 부재**, **(4) 망분리 강제 모드 부재**가 공공부문 운영 레벨로의 도약을 막는 병목이다.

---

## 2. 현황 진단

### 2.1 잘 구현된 영역

| 영역 | 위치 | 평가 |
|---|---|---|
| **원본 보존 원칙** | `opensast/llm/triage.py:30-36` | Finding 제거 금지 원칙이 주석과 코드에서 이중 강제 |
| **프로바이더 추상화** | `opensast/llm/base.py`, `ollama.py`, `anthropic.py`, `noop.py` | `LLMClient` 추상 + 플러그인 레지스트리 기반 확장성 |
| **자동 폴백** | `opensast/llm/triage.py:212-238` | 프로바이더 초기화 실패 시 noop으로 자동 강등 |
| **재시도** | `opensast/llm/triage.py:89-107` | tenacity 3회, 지수백오프 2-30초 |
| **캐시** | `opensast/llm/triage.py:110-150` | SHA-256 기반 캐시 키, Redis 24h TTL |
| **한국어 프롬프트** | `opensast/llm/prompts.py:5-48` | MOIS 2021 가이드 준거, 5대 판별 기준 명시 |
| **JSON 파싱 견고성** | `opensast/llm/triage.py:180-209`, `243-250` | 정규식 추출 + 실패 시 `needs_review` + `default_fp` 안전망 |
| **설정 외부화** | `opensast/config.py:143-151` | 6개 환경변수로 프로바이더·모델·타임아웃·컨텍스트 제어 |

### 2.2 해결해야 할 핵심 약점

| 영역 | 문제 요지 | 영향 |
|---|---|---|
| **단일 프롬프트** | MOIS 49개 항목이 동일 `USER_TEMPLATE` 사용 | SR1-1(SQLi)과 SR5-3(역직렬화) 오탐 판별 기준이 달라 정확도 손실 |
| **순차 triage 루프** | `for finding in findings:` (triage.py:50) | 대형 PR(findings ≥ 100)에서 직렬 호출 누적 지연 |
| **Ollama 관측성 부재** | `LLMResponse.input/output_tokens` 미기록 | 로컬 모델 품질·비용 벤치마크 불가 |
| **에어갭 강제 모드 부재** | cloud 프로바이더 우회 방지 가드 없음 | 망분리 환경 감사 대응 불가 |
| **프롬프트 버전 관리** | SYSTEM_PROMPT 하드코딩 | A/B 테스트·회귀 비교 불가 |
| **개인정보 마스킹 부재** | 코드 컨텍스트(snippet)가 그대로 LLM에 전달 | 실제 PII/비밀이 LLM 로그에 노출 가능 |
| **캐시 실패 silent swallow** | `except Exception: pass` (triage.py:138-139, 149-150) | Redis 장애 무인지 |

---

## 3. Gap 매트릭스

심각도: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

### 3.1 정확도 (Accuracy)

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| A1 | `prompts.py:19-48` | MOIS 카테고리별(입력검증/암호/세션/에러처리 등) 프롬프트 분기 부재 | 🟠 |
| A2 | `prompts.py` | Few-shot 예시(진양성/오탐 각 1~2건) 없음 | 🟠 |
| A3 | `triage.py:152-178` | 코드 컨텍스트가 `start_line ± window_lines` 고정. Taint source/sink 양방향 확장 미지원 | 🟡 |
| A4 | `triage.py:61-72` | `recommended_fix`/`patched_code` 품질 측정 메트릭 부재 | 🟡 |
| A5 | `prompts.py` | 프롬프트 버전(`prompt_version`) 필드가 TriageResult에 없음 | 🟡 |

### 3.2 성능 (Performance)

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| P1 | `triage.py:46-87` | Finding 순차 호출. 병렬/배치 파이프라인 부재 | 🔴 |
| P2 | `ollama.py:17-45` | `stream: False` 고정. 긴 응답 지연 | 🟡 |
| P3 | `triage.py:118-150` | Redis 연결 풀 없이 매 호출마다 `redis.from_url` | 🟡 |
| P4 | `triage.py:110-116` | 캐시 키가 `rule_id + file + line + snippet[:200]`. 동일 룰·다른 파일의 반복 판정 중복 호출 | 🟢 |

### 3.3 관측성 (Observability)

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| O1 | `ollama.py:37-45` | `input_tokens`/`output_tokens`/latency 미기록 (Anthropic은 anthropic.py:41-47에서 캡처) | 🟠 |
| O2 | `triage.py` 전반 | Prometheus 메트릭(`aisast_llm_calls_total`, `aisast_llm_latency_seconds`, `aisast_llm_cache_hits_total`) 미연동 | 🟠 |
| O3 | `triage.py:138-139, 149-150` | Redis 캐시 예외 silent swallow → 로깅 필요 | 🟡 |
| O4 | `triage.py:227-237` | 프로바이더 폴백 사유가 Finding에 미기록 (감사 추적 불가) | 🟡 |

### 3.4 공공부문 특화 (Compliance)

| # | 위치 | Gap | 심각도 |
|---|---|---|---|
| C1 | `config.py:143-151`, `triage.py:212-238` | 에어갭(망분리) 강제 모드 부재. `OPENSAST_LLM_STRICT_OFFLINE=1` 설정 시 anthropic 프로바이더 거부 필요 | 🔴 |
| C2 | `triage.py:152-178` | 코드 컨텍스트 내 PII/비밀(주민번호, API 키) 마스킹 부재 | 🟠 |
| C3 | `prompts.py` | MOIS SR1-15(개인정보 노출), SR3-3(오류메시지 정보노출) 등에 대한 공공부문 특화 지침 없음 | 🟠 |
| C4 | — | LLM 호출 감사 로그(요청 해시·모델·버전·사용자)의 외부 저장소 연동 부재 | 🟡 |

---

## 4. 단계별 고도화 로드맵

### Phase 1 — Quick Wins (1주)

즉시 효과가 있고 기존 구조 변경이 적은 항목.

| PR | 내용 | 영향 파일 |
|---|---|---|
| PR-L1 | **Ollama 토큰/latency 메트릭 기록**: `/api/chat` 응답의 `prompt_eval_count`/`eval_count`/`total_duration`을 `LLMResponse.input_tokens`/`output_tokens`/추가 필드로 기록 | `ollama.py:37-45`, `base.py` |
| PR-L2 | **캐시 실패 로깅 복원**: `except Exception: pass` → `log.warning` 전환 | `triage.py:138-139, 149-150` |
| PR-L3 | **폴백 사유 기록**: build_client 폴백 시 `Settings`에 `llm_active_provider` 기록 및 Finding.triage.rationale prefix | `triage.py:212-238` |
| PR-L4 | **TriageResult에 `prompt_version` 필드 추가**: prompts.py 상단에 `PROMPT_VERSION = "2026.04"` 상수 도입 | `models.py`, `prompts.py`, `triage.py:202-209` |
| PR-L5 | **에어갭 스위치 도입**: `OPENSAST_LLM_STRICT_OFFLINE` 환경변수. build_client에서 provider != "ollama" 시 `LLMError` 즉시 발생 | `config.py`, `triage.py:212-238` |

**완료 기준**: 5개 PR 머지, 신규 메트릭이 `/metrics` 엔드포인트(v0.5.0 관측성 트랙)에 노출, `OPENSAST_LLM_STRICT_OFFLINE=1` 환경에서 anthropic 선택 시 파이프라인이 즉시 거부됨을 테스트로 검증.

---

### Phase 2 — 정확도 & 프롬프트 체계화 (2~3주)

| PR | 내용 | 구현 방식 |
|---|---|---|
| PR-L6 | **카테고리별 프롬프트 분기** | `prompts.py`를 패키지로 분리 → `prompts/system.py`, `prompts/input_validation.py`, `prompts/crypto.py`, `prompts/session.py`, `prompts/error_handling.py`, `prompts/code_error.py`, `prompts/encapsulation.py`, `prompts/api_misuse.py`. `get_prompt(mois_item) -> (system, user_template)` 라우터 도입 |
| PR-L7 | **Few-shot 예시 주입** | 각 카테고리 프롬프트에 진양성 1건 + 오탐 1건(앵커 예시) 삽입. 예시는 `tests/fixtures/triage_examples/*.yaml` 에서 로드 |
| PR-L8 | **프롬프트 카탈로그 CLI** | `opensast prompts list`, `opensast prompts show <mois_id>` 서브커맨드 추가. 프롬프트 변경 PR의 리뷰 가시성 확보 |
| PR-L9 | **Taint 확장 컨텍스트 (옵션)** | `OPENSAST_LLM_CONTEXT_MODE=smart`일 때 엔진의 dataflow 정보(CodeQL flow path)를 snippet으로 병합. 없으면 기존 window fallback |
| PR-L10 | **프롬프트 회귀 테스트** | `tests/llm/golden/*.json` — 고정 Finding 입력 → 프롬프트 문자열 스냅샷. 프롬프트 수정 시 diff 강제 검토 |

**완료 기준**: MOIS 카테고리 7개에 대해 각각 전용 프롬프트 존재, `pytest tests/llm -v` 통과, 사내 라벨링 데이터셋(50건) 기준 정확도 베이스라인 대비 +5%p 이상 개선.

---

### Phase 3 — 성능·확장성 (3~4주)

| PR | 내용 | 구현 방식 |
|---|---|---|
| PR-L11 | **Triager 배치 병렬화** | `triage.py:46-87`의 for-loop를 `asyncio.gather` 또는 `concurrent.futures.ThreadPoolExecutor(max_workers=N)`로 전환. `OPENSAST_LLM_MAX_CONCURRENCY` (기본 4) 도입. Ollama 부하를 고려해 클라이언트 레벨 세마포어 적용 |
| PR-L12 | **Ollama 스트리밍 지원 (선택)** | `stream: True` + SSE 파싱. 단 JSON 응답 조립 안정성 검증 후 opt-in (`OPENSAST_OLLAMA_STREAM=1`) |
| PR-L13 | **Redis 커넥션 풀링** | `triage.py` 생성자에서 `redis.ConnectionPool` 1회 초기화, 인스턴스 재사용 |
| PR-L14 | **배치 캐시 조회** | `MGET`으로 findings 전체 캐시를 1회 왕복으로 조회 (현재 N회 왕복) |
| PR-L15 | **모델 워밍업/헬스체크** | 파이프라인 시작 전 `/api/tags` 로 모델 존재 확인. 미설치 시 명확한 에러 + 설치 가이드 링크 |

**완료 기준**: findings 100건 기준 total triage 시간이 현재 대비 60% 이상 단축(목표: 100건 → <30초, Ollama 로컬 기준), Redis MGET으로 캐시 조회 왕복 수 감소를 메트릭으로 입증.

---

### Phase 4 — 관측성·거버넌스 (2주)

| PR | 내용 | 구현 방식 |
|---|---|---|
| PR-L16 | **Prometheus 메트릭 추가** | `aisast_llm_calls_total{provider,model,verdict}`, `aisast_llm_latency_seconds_bucket`, `aisast_llm_tokens_total{direction}`, `aisast_llm_cache_hits_total`, `aisast_llm_fallback_total` |
| PR-L17 | **감사 로그 포맷** | `llm_audit.jsonl` — `{ts, finding_id, provider, model, prompt_version, cache_hit, latency_ms, tokens_in, tokens_out, verdict, fp_probability, fallback_reason}` 구조화 로그. 파일/Loki/CloudWatch 어댑터 분리 |
| PR-L18 | **프롬프트 버전 게이팅** | Phase 2에서 도입한 `prompt_version`을 리포트(SARIF `properties`)와 감사 로그에 반영. 버전별 KPI 분리 집계 |
| PR-L19 | **Grafana 대시보드 템플릿** | `monitoring/grafana/llm_dashboard.json` — latency p50/p95, verdict 분포, 캐시 히트율, 토큰 사용량 패널 |

**완료 기준**: 주요 5개 메트릭이 `/metrics` 노출, 대시보드 JSON import 후 주요 패널이 정상 렌더링, 감사 로그 샘플이 CI artifact로 첨부.

---

### Phase 5 — 공공부문 특화 (2~3주)

| PR | 내용 | 구현 방식 |
|---|---|---|
| PR-L20 | **PII/비밀 마스킹 파이프라인** | `_collect_context` 전후에 `opensast/llm/redact.py` 삽입. 탐지 대상: 주민등록번호, 카드번호, 전화번호, API 키 패턴, AWS access key, 이메일(옵션). Before/After 해시를 감사 로그에 기록 |
| PR-L21 | **MOIS 개인정보/오류처리 카테고리 강화 프롬프트** | SR1-15(개인정보 노출), SR3-1~3-3(에러메시지 정보노출) 전용 지침 추가. 개인정보보호법·표준개인정보 유형 참조 |
| PR-L22 | **에어갭 강제 모드 Hardening** | Phase 1 스위치 위에 `validate_airgap()` 호출: (1) anthropic provider 차단, (2) outbound DNS/HTTP 기본 거부, (3) `pip install anthropic` 설치 여부 점검 후 경고 |
| PR-L23 | **모델 서명·무결성 검증** | `OPENSAST_OLLAMA_MODEL_SHA256` 지정 시 `ollama show` 출력과 대조. 미일치 시 파이프라인 실패 |
| PR-L24 | **로컬 모델 성능 비교 러너** | `opensast llm benchmark` CLI — 라벨링 데이터셋 실행 후 gemma2:9b / qwen2.5:14b / llama3.1:8b 등 정확도·latency 비교표 출력 |

**완료 기준**: 망분리 시뮬레이션 환경(외부 HTTPS 차단)에서 end-to-end 파이프라인 성공, 마스킹된 컨텍스트가 LLM에 전달됨을 테스트로 검증, 벤치마크 CLI가 5개 모델 비교 리포트 생성.

---

## 5. KPI 및 검증 방법

| KPI | 현재 | 목표 (v0.9) | 측정 방법 |
|---|---|---|---|
| 오탐 판별 정확도 (Precision@TP) | 미측정 | ≥ 0.85 | 사내 라벨링 셋 50건 |
| 오탐 판별 재현율 (Recall@FP) | 미측정 | ≥ 0.75 | 사내 라벨링 셋 50건 |
| Findings 100건 triage 시간 | ~수분 (추정) | < 30s (로컬) | `opensast scan` 벤치마크 |
| LLM 캐시 히트율 | 미측정 | ≥ 60% (반복 실행 시) | Prometheus `cache_hits_total / calls_total` |
| 에어갭 강제 모드 통과율 | 0% | 100% | 망분리 CI job |
| 프롬프트 버전 커버리지 | 0 (단일) | 7개 카테고리 분기 | `opensast prompts list` |

**검증 자동화**:
- `.github/workflows/llm_regression.yml` — 라벨링 셋 기반 주간 회귀 (옵션: Ollama 설치된 self-hosted 러너)
- `tests/llm/test_strict_offline.py` — `OPENSAST_LLM_STRICT_OFFLINE=1` 시 anthropic 거부 검증
- `tests/llm/test_masking.py` — redact.py로 PII 마스킹 전·후 단위 테스트

---

## 6. 리스크 및 완화

| 리스크 | 발생 가능성 | 영향 | 완화 |
|---|---|---|---|
| 병렬화로 Ollama 부하 과다 | 중 | 중 | `max_concurrency` 기본 4, 벤치마크로 최적값 도출 |
| 프롬프트 분기가 정확도를 오히려 낮춤 | 중 | 높음 | 카테고리 롤아웃 전 A/B 회귀, 기본 single-prompt fallback 유지 |
| PII 마스킹이 코드 의미를 훼손 | 중 | 중 | 마스킹은 값(literal)만 치환, identifier 유지. 마스킹 전/후 Finding 매칭 일관성 테스트 |
| 에어갭 강제 모드가 개발 환경 DX 저해 | 높음 | 낮음 | `local` 프로파일에서는 기본 off, `enterprise`/`public-sector` 프로파일에서 on |
| 모델 교체 시 프롬프트 재튜닝 필요 | 높음 | 중 | 프롬프트 버전 + 벤치마크 CLI로 회귀 자동화, 모델 변경을 PR로 분리 |

---

## 7. 부록 — 구현 참조 위치

| 주제 | 파일 | 라인 |
|---|---|---|
| Triager 메인 루프 | `opensast/llm/triage.py` | 46-87 |
| 재시도 | `opensast/llm/triage.py` | 89-107 |
| 캐시 | `opensast/llm/triage.py` | 110-150 |
| 컨텍스트 수집 | `opensast/llm/triage.py` | 152-178 |
| 응답 파싱 | `opensast/llm/triage.py` | 180-209 |
| 프로바이더 빌더 | `opensast/llm/triage.py` | 212-238 |
| Ollama 클라이언트 | `opensast/llm/ollama.py` | 1-46 |
| Anthropic 클라이언트 | `opensast/llm/anthropic.py` | 1-48 |
| 프롬프트 템플릿 | `opensast/llm/prompts.py` | 1-48 |
| LLM 설정 | `opensast/config.py` | 143-151 |
| MOIS 카탈로그 | `opensast/mois/catalog.py` | — |
| 기존 테스트 | `tests/test_llm_triage.py`, `tests/test_triage_cache.py` | — |

---

**작성자**: openSAST 코어 팀 (Claude Code 협업)
**다음 리뷰**: Phase 1 완료 시점 (예상 2026-04-27) — KPI 베이스라인 측정 결과 반영
