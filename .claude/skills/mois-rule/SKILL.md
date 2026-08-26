---
name: mois-rule
description: MOIS 49개 보안약점 탐지 룰을 새로 쓰거나 고칠 때의 절차. Opengrep(Semgrep) YAML 룰 작성, mois_id·CWE 매핑, positive/negative 픽스처, 오탐 억제, 커버리지 갱신까지. Use when writing or tuning a detection rule, mapping a MOIS item to CWE, or reducing false positives.
argument-hint: [SR1-1 또는 룰 주제]
paths:
  - "rules/**"
  - "opensast/mois/**"
allowed-tools: Bash(semgrep *) Bash(.venv/bin/python *) Read Write Edit Grep Glob
---

# MOIS 탐지 룰 작성 절차

대상: $ARGUMENTS

## 1. 항목을 먼저 확정한다

```bash
.venv/bin/python -m opensast list-mois | grep -i "<키워드>"
.venv/bin/python -c "from opensast.mois import MOIS_ITEMS; print([i for i in MOIS_ITEMS if i.id=='SR1-1'])"
```

- `mois_id` 는 **`opensast/mois/catalog.py` 에 실재하는 ID** 여야 한다. 지어내지 않는다.
- 항목 수는 정확히 49다. 카탈로그를 늘리는 것은 별도 결정(ADR)이다.
- 이미 그 항목을 커버하는 룰이 있는지 먼저 확인한다:
  `grep -rn "mois_id: \"SR1-1\"" rules/`

## 2. 룰을 쓴다

`rules/opengrep/{java,python,javascript,go,common}/` 중 해당 언어 디렉터리에.

```yaml
rules:
  - id: mois-<약점-축약>-<변형>        # mois- 접두사 필수
    metadata:
      mois_id: "SR1-1"
      cwe: "CWE-89"
      category: "입력데이터 검증 및 표현"
      severity: "HIGH"                 # HIGH / MEDIUM / LOW
      confidence: "HIGH"
      description: "한 줄 설명"
    patterns:
      - pattern-inside: |              # 컨텍스트를 먼저 좁힌다
          ...
      - pattern: |
          ...
      - pattern-not: |                 # 안전한 관용구를 뺀다
          ...
    message: |
      무엇이 왜 위험한가. 그리고 **어떻게 고치는가** (파라미터 바인딩, 이스케이프,
      화이트리스트 검증 등 구체적으로).
    languages: [java]
    severity: ERROR
```

## 3. 픽스처를 함께 낸다 — 이게 없으면 룰이 아니다

```
tests/fixtures/vulnerable-samples/<lang>/<rule_id>/positive.<ext>   # 반드시 탐지돼야 함
tests/fixtures/vulnerable-samples/<lang>/<rule_id>/negative.<ext>   # 절대 탐지되면 안 됨
```

`negative` 는 "안전하게 고친 같은 코드"로 만든다. 그래야 `message` 가 제시한
조치 방안이 실제로 통하는지 증명된다.

## 4. 검증

```bash
semgrep --validate --config rules/opengrep                          # 문법
semgrep --config rules/opengrep/<lang>/<file>.yml tests/fixtures/vulnerable-samples/<lang>/<rule_id>/
.venv/bin/python -m pytest tests/test_mois_catalog.py tests/test_catalog_overlay.py -q
.venv/bin/python -c "from opensast.mois import MOIS_ITEMS; assert len(MOIS_ITEMS)==49"
```

positive 에서 탐지 1건 이상, negative 에서 0건이어야 한다.

## 5. 오탐 자가 점검

- `pattern` 만으로 잡고 있지 않은가 → `pattern-inside` 로 좁혔는가
- 프레임워크 기본 이스케이프·파라미터 바인딩·화이트리스트를 `pattern-not` 으로 뺐는가
- `severity`·`confidence` 가 실제 탐지 강도를 반영하는가 (전부 HIGH 는 잡음이다)
- 같은 약점을 다른 엔진이 이미 잡는가 → 중복은 `sarif/merge.py` 가 병합하지만,
  겹치는 이유를 룰 `description` 에 남긴다

## 6. 마무리

- 커버리지 변화를 보고한다 (현재 46/49).
- 미커버 3건(SR1-15, SR5-3, SR5-6)은 C/C++ 메모리 취약점이며 **지원 언어 밖**이다.
  이 3건을 커버하려면 C/C++ 엔진 도입 결정(ADR)이 먼저다.
- `docs/guide/custom-rules.md` · `docs/guide/mois-catalog.md` 갱신이 필요하면
  docs-curator 에 넘긴다.
- **`tests/vulnerable-samples/` 의 기존 취약 코드를 "고치지" 않는다.** 정탐 근거다.
