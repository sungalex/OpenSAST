"""SARIF 리포트 생성."""

from __future__ import annotations

import json

from opensast.db import models
from opensast.mois.catalog import Severity
from opensast.models import CodeLocation, Finding, TriageResult
from opensast.sarif.normalize import findings_to_sarif


def _to_domain(row: models.Finding) -> Finding:
    triage = None
    if row.triage is not None:
        triage = TriageResult(
            verdict=row.triage.verdict,
            fp_probability=row.triage.fp_probability,
            rationale=row.triage.rationale,
            recommended_fix=row.triage.recommended_fix,
            patched_code=row.triage.patched_code,
            model=row.triage.model,
        )
    location = CodeLocation(
        file_path=row.file_path,
        start_line=row.start_line,
        end_line=row.end_line,
        snippet=row.snippet,
    )
    finding = Finding(
        rule_id=row.rule_id,
        engine=row.engine,
        message=row.message,
        severity=Severity(row.severity),
        location=location,
        cwe_ids=tuple(row.cwe_ids or ()),
        mois_id=row.mois_id,
        category=row.category,
        language=row.language,
    )
    finding.triage = triage
    return finding


def build_sarif(scan: models.Scan, findings: list[models.Finding]) -> bytes:
    domain_findings = [_to_domain(f) for f in findings]
    doc = findings_to_sarif(domain_findings, tool_name=f"opensast/{scan.id}")
    return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
