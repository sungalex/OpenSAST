"""SARIF → Finding 변환 및 Finding → SARIF 직렬화."""

from __future__ import annotations

from typing import Any

from opensast.mois.catalog import Severity, items_for_cwe
from opensast.models import CodeLocation, Finding
from opensast.sarif.parser import SarifDocument, SarifResult, SarifRule


_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.LOW,
}


def findings_from_sarif(
    doc: SarifDocument,
    *,
    engine: str | None = None,
    language: str | None = None,
) -> list[Finding]:
    """SARIF 문서 내 모든 result를 Finding 리스트로 변환."""

    findings: list[Finding] = []
    for run in doc.runs:
        effective_engine = engine or run.tool_name
        for result in run.results:
            findings.append(
                _result_to_finding(result, effective_engine, language)
            )
    return findings


def _result_to_finding(
    result: SarifResult, engine: str, language: str | None
) -> Finding:
    severity = _LEVEL_TO_SEVERITY.get(result.level, Severity.MEDIUM)
    location = CodeLocation(
        file_path=result.location.file_path,
        start_line=result.location.start_line,
        end_line=result.location.end_line,
        start_column=result.location.start_column,
        end_column=result.location.end_column,
        snippet=result.location.snippet,
    )
    cwe_ids = result.rule.cwe_ids if result.rule else ()
    finding = Finding(
        rule_id=result.rule_id,
        engine=engine,
        message=result.message or (result.rule.name if result.rule else result.rule_id),
        severity=severity,
        location=location,
        cwe_ids=cwe_ids,
        language=language,
        raw={"properties": result.properties},
    )
    _apply_mois_mapping(finding, result.rule)
    return finding


def _apply_mois_mapping(finding: Finding, rule: SarifRule | None) -> None:
    if rule is not None:
        props = rule.tags or ()
        for tag in props:
            if tag.lower().startswith("mois-"):
                mois_id = tag.upper().replace("MOIS-", "")
                finding.mois_id = mois_id
                break
    for cwe in finding.cwe_ids:
        matches = items_for_cwe(cwe)
        if matches:
            finding.with_mois(matches[0])
            break


def findings_to_sarif(
    findings: list[Finding], *, tool_name: str = "opensast"
) -> dict[str, Any]:
    """Finding 리스트를 SARIF 2.1.0 문서로 직렬화."""

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message[:120]},
                "helpUri": "",
                "properties": {
                    "tags": [*(f"CWE-{c.split('-')[-1]}" for c in f.cwe_ids)],
                    "mois_id": f.mois_id,
                    "engine": f.engine,
                },
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.file_path},
                            "region": {
                                "startLine": f.location.start_line,
                                "endLine": f.location.end_line,
                                "startColumn": f.location.start_column,
                                "endColumn": f.location.end_column,
                                "snippet": {"text": f.location.snippet}
                                if f.location.snippet
                                else None,
                            },
                        }
                    }
                ],
                "properties": {
                    "finding_id": f.finding_id,
                    "mois_id": f.mois_id,
                    "cwe_ids": list(f.cwe_ids),
                    "triage": f.triage.as_dict() if f.triage else None,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "0.1.0",
                        "informationUri": "https://github.com/sungalex/OpenSAST",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _severity_to_level(sev: Severity) -> str:
    return {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }[sev]
