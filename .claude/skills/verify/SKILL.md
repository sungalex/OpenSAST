---
name: verify
description: 변경을 CI 와 동등한 수준으로 로컬 검증한다. pytest 전량, 프론트 타입체크·테스트, 룰 문법, MOIS 카탈로그 단언, 그리고 선택적으로 자기 진단(self-SAST). PR 을 내기 전에 항상 실행한다. Use before opening a PR, after any code change, or when asked "does this actually work".
argument-hint: [full | quick | self-scan]
allowed-tools: Bash(.venv/bin/python *) Bash(npm test *) Bash(npx tsc *) Bash(semgrep *) Bash(opensast *) Bash(git status *) Bash(git diff *) Read Grep Glob
---

# 로컬 검증 (CI 동등)

모드: $ARGUMENTS (미지정 시 `full`)

무엇이 바뀌었는지부터 본다.

```bash
git status --short && git diff --stat
```

## 1단계 — 백엔드 (모든 변경에 필수)

```bash
.venv/bin/python -m pytest -q --tb=short
```

약 90초. **실패하면 여기서 멈춘다.** 테스트를 느슨하게 고쳐 통과시키지 않는다.

`quick` 모드면 변경 영역만:

```bash
.venv/bin/python -m pytest tests/test_authorization_boundary.py tests/test_security_regressions.py -q --tb=short
```

## 2단계 — 영역별 추가 검증

| 무엇을 바꿨나 | 추가 명령 |
|---|---|
| `opensast/api·services·db` | `.venv/bin/python -m pytest tests/test_authorization_boundary.py tests/test_security_regressions.py tests/test_api_*.py -q` |
| `alembic/` | `.venv/bin/python -m pytest tests/test_alembic_chain.py tests/test_db_migrate.py -q` |
| `rules/` | `semgrep --validate --config rules/opengrep` |
| `opensast/mois/` | `.venv/bin/python -c "from opensast.mois import MOIS_ITEMS; assert len(MOIS_ITEMS)==49"` |
| `opensast/engines·orchestrator·sarif·llm` | `.venv/bin/python -m pytest tests/test_pipeline_second_pass.py tests/test_merge_severity.py tests/test_sarif_*.py tests/test_llm_triage.py tests/test_triage_cache.py -q` |
| `frontend/` | `cd frontend && npm test && npx tsc -b --noEmit` |

## 3단계 — 무거운 마커 (기본 실행에서 제외되어 있다)

```bash
.venv/bin/python -m pytest -m engine -q               # 실제 엔진 바이너리 필요
.venv/bin/python -m pytest -m celery_integration -q   # 실제 Redis + Celery 필요
```

`pyproject.toml` 의 기본 `addopts` 가 이 둘을 빼고 있다. **여기가 이 저장소의
가장 큰 검증 공백**이므로, 손댄 영역이 엔진·Celery 라면 반드시 돌린다.

## 4단계 — 커버리지 (CI 와 동일)

```bash
.venv/bin/python -m pytest -q --tb=short --cov=opensast --cov-report=term-missing
```

## 5단계 — 자기 진단 (`self-scan` 모드, 또는 보안 관련 변경 시)

CI 의 `self-sast` 잡은 **HIGH 0건**을 요구한다.

```bash
opensast scan ./opensast --no-second-pass --no-triage -o /tmp/self-scan.sarif --json /tmp/self-scan.json
.venv/bin/python - <<'PY'
import json
d = json.load(open('/tmp/self-scan.json'))
high = [f for f in d['findings'] if f['severity'] == 'HIGH']
print(f"HIGH: {len(high)}")
for f in high:
    print(" ", f.get('rule_id'), f.get('location'))
PY
```

> semgrep 은 `click<8.2` 를 고정해 typer 와 충돌한다. 같은 venv 에 넣지 말고
> `pipx install "semgrep>=1.70"` 로 격리 설치한다.

HIGH 가 나오면 정탐/오탐 판정이 먼저다 (security-auditor). 억제로 덮지 않는다.

## 보고

- 실행한 명령과 결과 (통과/실패 수, 소요 시간)
- 실패했다면: 원인 파일, 담당 에이전트, **고치지 않고 남긴 이유**
- 커버리지 변화
