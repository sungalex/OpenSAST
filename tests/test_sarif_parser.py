"""SARIF 파서 및 정규화 테스트."""

from pathlib import Path

from opensast.mois.catalog import Severity
from opensast.sarif.merge import coverage_by_mois, merge_findings
from opensast.sarif.normalize import findings_from_sarif, findings_to_sarif
from opensast.sarif.parser import parse_sarif


def test_parse_fixture(fixtures_dir: Path) -> None:
    doc = parse_sarif(fixtures_dir / "opengrep-sample.sarif.json")
    assert len(doc.runs) == 1
    run = doc.runs[0]
    assert run.tool_name == "semgrep"
    assert len(run.results) == 2


def test_normalize_maps_mois(fixtures_dir: Path) -> None:
    doc = parse_sarif(fixtures_dir / "opengrep-sample.sarif.json")
    findings = findings_from_sarif(doc, engine="opengrep", language="python")
    assert len(findings) == 2
    sql = next(f for f in findings if "sql" in f.rule_id.lower())
    assert sql.mois_id == "SR1-1"
    assert "CWE-89" in sql.cwe_ids
    assert sql.severity == Severity.HIGH


def test_merge_dedupes_duplicates(fixtures_dir: Path) -> None:
    doc = parse_sarif(fixtures_dir / "opengrep-sample.sarif.json")
    group_a = findings_from_sarif(doc, engine="opengrep", language="python")
    group_b = findings_from_sarif(doc, engine="bandit", language="python")
    merged = merge_findings([group_a, group_b])
    # same file/line/cwe so one of them should win
    assert len(merged) == 2
    coverage = coverage_by_mois(merged)
    assert coverage.get("SR1-1", 0) >= 1


def test_sarif_roundtrip(fixtures_dir: Path) -> None:
    doc = parse_sarif(fixtures_dir / "opengrep-sample.sarif.json")
    findings = findings_from_sarif(doc, engine="opengrep")
    serialized = findings_to_sarif(findings, tool_name="opensast-test")
    assert serialized["version"] == "2.1.0"
    assert serialized["runs"][0]["tool"]["driver"]["name"] == "opensast-test"
    assert len(serialized["runs"][0]["results"]) == len(findings)
