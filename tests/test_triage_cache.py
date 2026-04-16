"""v0.5.0 Triage 캐시 및 retry 테스트."""

from aisast.llm.triage import Triager
from aisast.models import CodeLocation, Finding, TriageResult
from aisast.mois.catalog import Severity


def _make_finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "test-rule",
        "engine": "opengrep",
        "message": "test finding",
        "severity": Severity.HIGH,
        "location": CodeLocation(file_path="test.java", start_line=10, snippet="int x=1;"),
        "cwe_ids": ("CWE-89",),
        "mois_id": "SR1-1",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestTriageCacheKey:
    def test_cache_key_deterministic(self):
        f = _make_finding()
        k1 = Triager._cache_key(f)
        k2 = Triager._cache_key(f)
        assert k1 == k2
        assert k1.startswith("triage:")

    def test_cache_key_differs_by_line(self):
        f1 = _make_finding()
        f2 = _make_finding(
            location=CodeLocation(file_path="test.java", start_line=20, snippet="int x=1;")
        )
        assert Triager._cache_key(f1) != Triager._cache_key(f2)

    def test_cache_key_differs_by_rule(self):
        f1 = _make_finding(rule_id="rule-a")
        f2 = _make_finding(rule_id="rule-b")
        assert Triager._cache_key(f1) != Triager._cache_key(f2)


class TestParseResponse:
    def test_valid_json(self):
        text = '{"verdict": "true_positive", "fp_probability": 10, "rationale": "real bug"}'
        result = Triager._parse_response(text, "test-model")
        assert result.verdict == "true_positive"
        assert result.fp_probability == 10
        assert result.rationale == "real bug"

    def test_missing_fp_uses_default(self):
        text = '{"verdict": "needs_review"}'
        result = Triager._parse_response(text, "test", default_fp=42)
        assert result.fp_probability == 42

    def test_invalid_json_uses_default(self):
        result = Triager._parse_response("not json", "test", default_fp=75)
        assert result.fp_probability == 75
        assert result.verdict == "needs_review"

    def test_fp_clamped_to_100(self):
        text = '{"verdict": "fp", "fp_probability": 999}'
        result = Triager._parse_response(text, "test")
        assert result.fp_probability == 100

    def test_fp_clamped_to_0(self):
        text = '{"verdict": "tp", "fp_probability": -50}'
        result = Triager._parse_response(text, "test")
        assert result.fp_probability == 0
