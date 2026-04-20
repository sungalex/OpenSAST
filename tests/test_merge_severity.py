"""merge.py severity 비교 로직 테스트 — v0.4.2 회귀 방지."""

from opensast.mois.catalog import Severity
from opensast.models import CodeLocation, Finding
from opensast.sarif.merge import _prefers, merge_findings


def _make(engine: str, severity: Severity, line: int = 1) -> Finding:
    return Finding(
        rule_id="test-rule",
        engine=engine,
        message="test",
        severity=severity,
        location=CodeLocation(file_path="a.java", start_line=line),
        cwe_ids=("CWE-89",),
    )


class TestPrefers:
    def test_high_beats_medium(self):
        assert _prefers(_make("bandit", Severity.HIGH), _make("bandit", Severity.MEDIUM))

    def test_high_beats_low(self):
        assert _prefers(_make("bandit", Severity.HIGH), _make("bandit", Severity.LOW))

    def test_medium_beats_low(self):
        """v0.4.1 버그 수정 검증: 기존에는 LOW가 MEDIUM을 이겼음 (문자열 비교)."""
        assert _prefers(_make("bandit", Severity.MEDIUM), _make("bandit", Severity.LOW))

    def test_low_does_not_beat_medium(self):
        assert not _prefers(_make("bandit", Severity.LOW), _make("bandit", Severity.MEDIUM))

    def test_same_severity_no_preference(self):
        assert not _prefers(_make("bandit", Severity.HIGH), _make("bandit", Severity.HIGH))

    def test_engine_priority_trumps_severity(self):
        """높은 엔진 우선순위가 낮은 심각도보다 우선."""
        assert _prefers(_make("codeql", Severity.LOW), _make("eslint", Severity.HIGH))


class TestMergeFindings:
    def test_same_location_keeps_higher_severity(self):
        low = _make("bandit", Severity.LOW)
        medium = _make("bandit", Severity.MEDIUM)
        result = merge_findings([[low], [medium]])
        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM

    def test_same_location_keeps_higher_engine(self):
        bandit = _make("bandit", Severity.HIGH)
        codeql = _make("codeql", Severity.HIGH)
        result = merge_findings([[bandit], [codeql]])
        assert len(result) == 1
        assert result[0].engine == "codeql"

    def test_different_locations_kept(self):
        f1 = _make("bandit", Severity.HIGH, line=1)
        f2 = _make("bandit", Severity.HIGH, line=10)
        result = merge_findings([[f1, f2]])
        assert len(result) == 2
