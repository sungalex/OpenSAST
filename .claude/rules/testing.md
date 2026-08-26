---
paths:
  - "tests/**/*.py"
  - ".github/workflows/*.yml"
---

# 테스트 · CI

## 이 저장소의 1번 리스크

엔진과 Celery 가 전부 `MagicMock` 뒤에 있다. 단위 테스트가 전량 통과해도
**엔진 바이너리 호출 규약이 깨졌는지는 알 수 없다.** 새 테스트를 쓸 때 이
간극을 넓히지 않는지 먼저 생각한다.

## marker

`pyproject.toml` 의 기본값이 `addopts = "-m 'not engine and not celery_integration'"` 다.

| marker | 의미 |
|---|---|
| `engine` | 실제 엔진 바이너리(semgrep, bandit …) 필요 |
| `celery_integration` | 실제 Redis + Celery 워커 필요 |

무거운 테스트에는 반드시 marker 를 단다. 기본 실행(~90s)이 느려지면 아무도
돌리지 않는다.

## 절대 규칙

1. **테스트를 통과시키려고 프로덕션 코드를 느슨하게 만들지 않는다.**
2. **의도된 취약 픽스처를 고치지 않는다.** `tests/vulnerable-samples/` 와
   `tests/test_engine_integration.py` 는 탐지 룰 검증용이다. 스캐너 예외는
   `.gitguardian.yaml` 에 경로로 등록되어 있다.
3. **테스트 자격증명은 런타임 생성이다** (`tests/_credentials.py`).
   `*_PASSWORD` / `*_SECRET` / `*_TOKEN` 류 식별자가 있는 줄에 따옴표 문자열을
   같이 두지 않는다 — 시크릿 스캐너가 그 모양을 매칭한다.
4. **회귀는 고정한다.** 보안 결함은 `tests/test_security_regressions.py`,
   조직 간 격리는 `tests/test_authorization_boundary.py`.

## 실행

```bash
.venv/bin/python -m pytest -q --tb=short                                  # 전량 (~90s)
.venv/bin/python -m pytest -q --tb=short --cov=opensast --cov-report=term-missing
.venv/bin/python -m pytest -m engine -q
.venv/bin/python -m pytest -m celery_integration -q
cd frontend && npm test && npx tsc -b --noEmit
```

## CI 워크플로를 고칠 때

- backend 잡: ubuntu/macOS 는 full pytest, **Windows 는 import smoke 만** —
  semgrep·WeasyPrint 네이티브 미지원 때문이다. 이 구조를 임의로 바꾸지 않는다.
- `self-sast` 잡은 **HIGH 0건**을 요구한다. semgrep 은 `click<8.2` 를 고정해
  typer 와 충돌하므로 **pipx 로 격리 설치**한다 — 같은 venv 에 넣지 않는다.
- `ruff check opensast` 를 게이트로 승격하기 전에 기준선을 먼저 정리한다
  (2026-08-25 기준 207건, 대부분 FastAPI `Depends()` 기본값에 대한 B008 오탐).
  코드를 뜯어고치는 대신 룰 제외/`per-file-ignores` 로 처리한다.
- `mypy` 와 `pip-audit` 은 현재 실패 허용(non-blocking) 단계다.
- MOIS 항목 수 단언(`len(MOIS_ITEMS) == 49`)을 제거하지 않는다.
