# LLM 오탐 필터링

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0003](../adr/0003-documentation-architecture.md)).

> **정본 주의**
>
> 동시 실행·캐시·상한 동작의 근거는
> [ADR-0004](../adr/0004-triage-concurrency.md) 에 있다.

---

## LLM 오탐 필터링

`opensast/llm/triage.py::Triager`가 전체 파이프라인을 수행한다.

### 10.1 동작 흐름

1. **컨텍스트 수집**: 탐지 파일을 열어 `±OPENSAST_LLM_CONTEXT_WINDOW_LINES` 줄(기본 20)을 추출. 파일 접근이 실패하면 SARIF `snippet`만 사용.
2. **프롬프트 조립**: `opensast/llm/prompts.py::SYSTEM_PROMPT` + `USER_TEMPLATE` (한국어, 행안부 용어). 탐지 MOIS ID·CWE·파일·엔진·룰·메시지·코드 컨텍스트를 모두 포함.
3. **LLM 호출**: `build_client()` 가 `OPENSAST_LLM_PROVIDER` 에 따라 `AnthropicClient` / `OllamaClient` / `NoopLLMClient` 를 선택.
4. **결과 파싱**: 응답에서 첫 JSON 객체를 추출하여 `TriageResult`로 변환. 파싱 실패 시 `verdict=needs_review`, `fp_probability=OPENSAST_LLM_DEFAULT_FP_PROBABILITY`(기본 50).
5. **부착**: `Finding.triage` 필드에 저장. **원본 Finding은 삭제되지 않음**.

> **v0.5.0 Triage 개선**: Redis 캐싱(24시간 TTL)으로 동일 코드 패턴 재분석을
> 방지한다. LLM 호출은 `tenacity` 재시도 + 서킷브레이커로 일시 장애에 대응한다.

### 10.2 응답 JSON 스키마

```json
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "fp_probability": 0,
  "rationale": "근거 설명(한국어)",
  "recommended_fix": "조치 방안",
  "patched_code": "수정 예시 코드(선택)"
}
```

### 10.3 프로바이더

| 프로바이더 | 클래스 | 사용 조건 |
|-----------|--------|----------|
| **Anthropic Claude** | `AnthropicClient` | `OPENSAST_ANTHROPIC_API_KEY` 설정 + `anthropic` SDK 설치 |
| **Ollama** | `OllamaClient` | `OPENSAST_OLLAMA_HOST` 접근 가능 + `OPENSAST_OLLAMA_MODEL` pull됨 |
| **Noop** | `NoopLLMClient` | 폴백. 항상 `needs_review`, `fp_probability=50` |

---
