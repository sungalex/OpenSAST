"""LLM Triager 테스트 (Noop 클라이언트 기반)."""

from opensast.llm.noop import NoopLLMClient
from opensast.llm.triage import Triager, _extract_json_object
from opensast.mois.catalog import Severity
from opensast.models import CodeLocation, Finding


def _make_finding() -> Finding:
    return Finding(
        rule_id="mois-sr1-1-python-sql-fstring",
        engine="opengrep",
        message="SQL 삽입",
        severity=Severity.HIGH,
        location=CodeLocation(file_path="app/db.py", start_line=10, snippet="cursor.execute(f\"... {x}\")"),
        cwe_ids=("CWE-89",),
        mois_id="SR1-1",
        language="python",
    )


def test_triager_attaches_result() -> None:
    triager = Triager(client=NoopLLMClient())
    findings = triager.triage([_make_finding()])
    assert findings[0].triage is not None
    assert 0 <= findings[0].triage.fp_probability <= 100
    assert findings[0].triage.model == "noop"


def test_json_extract_tolerates_prefix() -> None:
    text = "분석 결과: {\"verdict\": \"true_positive\", \"fp_probability\": 10, \"rationale\": \"r\"}"
    payload = _extract_json_object(text)
    assert payload is not None
    assert payload["verdict"] == "true_positive"
