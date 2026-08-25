# ADR-0004: Triage 를 동시 실행으로 전환하고 조용한 실패를 없앤다

**Status:** Accepted
**Date:** 2026-08-25
**Deciders:** 백엔드 오너

## Context

LLM triage 계층에 세 문제가 겹쳐 있었고, 합쳐지면서 **문서상의 인식과 실제가
정반대**가 되어 있었다.

**1. 완전 직렬 실행.** `Triager.triage()` 는 Finding 을 하나씩 순회하며 LLM 을
호출했다. 각 호출은 tenacity 로 최대 3회 재시도하고 타임아웃은 60초다. Finding
1,000개면 낙관적으로도 30분을 넘기는데 `triage_task_soft_time_limit` 은
1,800초다. 즉 **대형 스캔은 반드시 타임아웃**했다. 배치·동시성·상한 중 어느
것도 없었다.

**2. 배포에서 캐시가 죽어 있었다.** `docker-compose.yml` 의 `api` 서비스에는
`OPENSAST_REDIS_URL` 이 있지만 `worker` 에는 없었다. 워커는 기본값
`redis://localhost:6379/0` 로 접속을 시도해 매번 실패했다. 게다가 Finding 하나당
새 클라이언트를 만들었으므로, 1,000건이면 실패 커넥션 2,000개를 만들고 버렸다.

**3. 그 실패가 조용히 삼켜졌다.**

```python
def _get_cached(self, key):
    try:
        ...
    except Exception:
        return None      # ← 로그 없음

def _set_cached(self, key, result):
    try:
        ...
    except Exception:
        pass             # ← 로그 없음
```

로그 한 줄 없이 캐시가 무효화되므로 아무도 몰랐다. ROADMAP 은 이 기능(L3)을
"해결됨" 으로 간주하고 있었고, 리스크 표에는 "v0.5 에서 Redis 캐싱을 먼저
구현해 LLM 비용을 통제한다" 고 적혀 있었다. 코드는 있었지만 배포에는 없었다.

**부수 문제.** `except LLMError` 만 잡았으므로 그 외 예외(포맷 오류, 파일 접근
실패 등) 하나가 나머지 Finding 의 triage 를 통째로 날렸다. 또
`_collect_context()` 는 `(source_root / file_path).resolve()` 를 봉쇄 검사 없이
읽어, 엔진이 절대 경로나 `../` 를 보고하면 루트 밖 파일 내용이 LLM 프롬프트에
실려 나갈 수 있었다(Anthropic 프로바이더에서는 외부 전송 경로).

## Decision

네 가지를 함께 바꾼다. 하나만 고치면 나머지가 문제를 다시 감춘다.

### 1. 동시 실행

```python
with ThreadPoolExecutor(max_workers=settings.llm_max_concurrency) as pool:
    pool.map(...)
```

`llm_max_concurrency` 기본값 4. LLM 호출은 I/O 대기가 지배적이므로 스레드로
충분하다. `1` 로 두면 예전과 동일한 순차 실행이라 되돌리기도 쉽다.

### 2. 커넥션 풀

`_redis_client(url)` 을 `lru_cache` 로 감싸 URL 당 클라이언트 하나(내부 커넥션
풀)를 재사용한다. `socket_connect_timeout=2` 로 죽은 Redis 에 오래 매달리지
않는다.

### 3. 조용한 실패 금지

캐시 접근이 실패하면 **최초 1회 WARNING** 을 남기고 그 실행 동안 캐시를
비활성으로 표시한다.

```
triage 캐시 비활성화 — Redis(redis://localhost:6379/0) 접근 실패: ...
워커 컨테이너에 OPENSAST_REDIS_URL 이 주입되어 있는지 확인하세요.
```

조용한 성능 저하보다 시끄러운 성능 저하가 낫다. 실패 원인과 조치 방법을 같이
적는다. 그리고 `docker-compose.yml` 의 워커에 `OPENSAST_REDIS_URL` 을 추가한다.

### 4. 축소 사실을 결과에 기록

`triage_max_findings`(기본 2,000)를 넘으면 severity 순으로 자르되, **잘렸다는
사실**을 `TriageReport.truncated` 와 `ScanResult.notes` 에 남긴다. 스캔 결과를
보는 사람이 "전부 판정됐다" 고 오해하지 않도록 한다.

같은 이유로 2차 Pass 가 생략될 때도 `ScanResult.notes` 에 사유를 남긴다.

### 함께 적용한 것

- 실패를 **Finding 단위로 격리** — `except Exception` 으로 잡고 해당 Finding 만
  `needs_review` 로 표시한다. 예외 타입명을 rationale 에 포함해 원인을 남긴다.
- `_collect_context()` 에 `Path.is_relative_to()` 봉쇄 검사 추가. 루트를 벗어난
  경로는 경고 후 snippet 폴백을 쓴다.
- `triage_batch_task` 가 리스트 순서(`zip`) 대신 DB 행 id 로 결과를 되돌린다.

## Options Considered

| 안 | 처리량 | 운영 복잡도 | 평가 |
|---|---|---|---|
| A. 순차 유지 + 타임아웃만 상향 | 낮음 | 낮음 | 근본 해결 아님. 대형 스캔은 여전히 몇 시간 |
| **B. 스레드 풀 + 캐시 배선 + 실패 가시화 (채택)** | 높음 | 낮음 | I/O 바운드에 맞는 최소 변경 |
| C. Celery 태스크로 Finding 단위 분산 | 매우 높음 | 높음 | 브로커 부하·결과 취합·부분 실패 처리가 새 문제로 온다 |

C 는 수만 건 규모에서 필요해질 수 있으나, 지금 병목은 "직렬" 이지 "단일 노드"가
아니다. 필요해지면 그때 별도 ADR 로 다룬다.

## Consequences

**쉬워지는 것**

- Finding 1,000개 규모가 soft time limit 안에 들어온다.
- 캐시 적중이 실제로 발생해 LLM 비용이 통제된다 — 문서가 주장하던 상태에
  코드가 도달한다.
- 캐시가 죽으면 **알 수 있다.**

**어려워지는 것**

- Ollama 단일 인스턴스에 동시 요청이 몰리면 오히려 느려질 수 있다.
  `llm_max_concurrency` 기본값을 프로바이더별로 다르게 잡아야 할 수 있고,
  지금은 사용자가 조정하도록 열어두었다.
- 스레드에서 LLM 클라이언트를 공유하므로, 향후 프로바이더 구현은 thread-safe
  해야 한다. `TriageReport` 갱신은 락으로 보호했다.

**다시 볼 것**

- 상한 초과 시 자르는 정책이 행안부 대응에서 허용되는지 확인이 필요하다.
  허용되지 않으면 상한 대신 태스크 분할(chunked task)로 가야 한다. 기본값
  2,000 은 잠정치다.
- 원본 보존 원칙은 triage 단계에서만 강제된다. 병합 단계에서의 손실은
  별도로 다뤘다(`merge_findings` 키에 `rule_id` 추가).

## Action Items

1. [x] 워커 서비스에 `OPENSAST_REDIS_URL` 추가
2. [x] Redis 클라이언트 커넥션 풀화
3. [x] 캐시 실패 최초 1회 경고 + 실행 단위 비활성
4. [x] `ThreadPoolExecutor` 도입, `llm_max_concurrency` 설정 추가
5. [x] `triage_max_findings` 상한 + `TriageReport.truncated` + `ScanResult.notes`
6. [x] Finding 단위 실패 격리, `_collect_context` 경로 봉쇄
7. [x] 회귀 테스트 (`tests/test_security_regressions.py`)
8. [ ] 행안부 대응 관점에서 triage 상한 정책 확인
