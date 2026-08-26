---
paths:
  - "opensast/engines/**/*.py"
  - "opensast/orchestrator/**/*.py"
  - "opensast/sarif/**/*.py"
  - "opensast/llm/**/*.py"
  - "opensast/mois/**/*.py"
  - "opensast/reports/**/*.py"
  - "rules/**/*.yml"
  - "rules/**/*.yaml"
  - "rules/**/*.ql"
---

# 분석 파이프라인 · 룰셋

## 2-Pass 모델

1. **1차 (Fast)**: Opengrep · Bandit · ESLint · gosec
2. **2차 (Deep)**: CodeQL · SpotBugs
3. **3단계**: LLM triage — 오탐 확률 · 판정 근거 · 조치 방안

한 Pass 안의 엔진은 **동시 실행**한다. 구성의 정본은
`opensast/engines/registry.py` 다.

## 조용한 축소 금지

2차 Pass 가 생략되거나 triage 가 상한(`triage_max_findings`)에 걸리면 그 사실이
**`ScanResult.notes` 에 기록**되어야 한다. 결과가 줄었는데 사용자가 모르는
상태는 진단 도구로서 결함이다.

## LLM triage 는 annotate 만 한다

원본 Finding 을 **절대 제거하지 않는다.** `triage` 필드에 덧붙일 뿐이다.
행안부 지침 대응에서 도구가 임의로 결과를 지우면 감리 근거가 무너진다.

## 룰 작성 규약 (Opengrep / Semgrep YAML)

`id` 는 `mois-` 접두사. 다음 메타데이터는 **필수**다.

```yaml
rules:
  - id: mois-sql-injection-mybatis
    metadata:
      mois_id: "SR1-1"                    # 49개 항목 ID — catalog.py 에 실재해야 함
      cwe: "CWE-89"
      category: "입력데이터 검증 및 표현"   # MOIS 7대 분류
      severity: "HIGH"                     # HIGH / MEDIUM / LOW
      confidence: "HIGH"
      description: "MyBatis 환경에서의 SQL 인젝션"
```

- 49개 항목의 단일 소스는 `opensast/mois/catalog.py` (정확히 49). YAML
  오버레이는 덮어쓰기용이지 정본이 아니다.
- 현재 커버리지 46/49. 미커버 3건(SR1-15, SR5-3, SR5-6)은 C/C++ 메모리
  취약점이며 지원 언어 밖이다.
- 오탐 억제: `pattern-inside` 로 컨텍스트를 좁히고, 안전한 관용구는
  `pattern-not` 으로 뺀다. 전부 HIGH 로 올리면 triage 가 걸러야 할 잡음만 는다.
- 새 룰에는 **positive·negative 픽스처를 함께** 낸다.

```bash
semgrep --validate --config rules/opengrep
semgrep --config rules/opengrep/<lang>/<file>.yml tests/vulnerable-samples/
```

## 엔진 어댑터

- `EnginePlugin` 계약: `scan()` 은 표준 결과 리스트, `is_available()` 은 설치 여부.
  `pyproject.toml` 의 `[project.entry-points."opensast.engines"]` 에 등록한다.
- 바이너리 호출은 `utils/subprocess.py` 경유.
- 새 엔진 출력은 반드시 `sarif/normalize.py` 를 통과시킨다 — 정규화되지 않은
  severity 가 `sarif/merge.py` 의 병합 규칙을 깨뜨린다.
- 타임아웃·경로·리소스 한계는 `Settings` 에서 읽는다. 어댑터에 숫자를 박지 않는다.
- **엔진 구성 교체는 아직 착수하지 않는다.** ADR-0001 은 Accepted(2026-08-26)로
  CodeQL·ESLint → Joern(Primary) + Opengrep taint mode(Secondary) 방향을 확정했지만
  **구현 미착수**다. 차단 요인은 ADR-0002 — Joern `v2.0.x` 를 전제로 쓰였는데 현행은
  `4.0.x` 라 **rev.2 재작성 후 Accepted** 되어야 하고, ADR-0004 는 여기 종속이다.
  버전이 고정되지 않은 엔진은 룰 오동작과 버전 부동을 구분할 수 없게 만든다.
  그전까지 CodeQL·ESLint 어댑터를 제거하지 않는다 (미설치 시 자동 skip 으로 완화).

## 리포트

SARIF 2.1.0 · HTML(Jinja2) · Excel(openpyxl) · PDF(WeasyPrint).
**WeasyPrint 가 없을 때 HTML 을 PDF 인 척 반환하지 않는다** — 명시적 오류이거나
정직한 `Content-Type` 이어야 한다 (ROADMAP v0.6).
