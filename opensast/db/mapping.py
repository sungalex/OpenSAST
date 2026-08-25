"""도메인 모델 ↔ ORM 모델 변환을 한곳에 모은다.

예전에는 이 변환이 세 곳(`repo._finding_from_domain`, `tasks.triage_batch_task`,
`sarif.normalize`)에 흩어져 있었고, 역방향 변환에서 `raw` 필드가 유실되는 등
이미 어긋나 있었다. 필드를 하나 추가할 때 고쳐야 할 곳을 하나로 줄인다.
"""

from __future__ import annotations

from opensast.db import models
from opensast.mois.catalog import Severity
from opensast.models import CodeLocation, Finding as DomainFinding, TriageResult


def finding_to_orm(scan_id: str, dom: DomainFinding) -> models.Finding:
    """도메인 Finding → ORM 행 (triage 포함)."""

    row = models.Finding(
        scan_id=scan_id,
        finding_hash=dom.finding_id,
        rule_id=dom.rule_id,
        engine=dom.engine,
        message=dom.message,
        severity=dom.severity.value,
        file_path=dom.location.file_path,
        start_line=dom.location.start_line,
        end_line=dom.location.end_line,
        cwe_ids=list(dom.cwe_ids),
        mois_id=dom.mois_id,
        category=dom.category,
        language=dom.language,
        snippet=dom.location.snippet,
        raw=dom.raw,
    )
    if dom.triage is not None:
        row.triage = triage_to_orm(dom.triage)
    return row


def finding_to_domain(row: models.Finding) -> DomainFinding:
    """ORM 행 → 도메인 Finding.

    `finding_id` 에는 DB 행 id 를 문자열로 넣는다. 배치 처리에서 결과를
    되돌릴 때 리스트 순서에 의존하지 않기 위해서다.
    """

    dom = DomainFinding(
        rule_id=row.rule_id,
        engine=row.engine,
        message=row.message,
        severity=Severity(row.severity),
        location=CodeLocation(
            file_path=row.file_path,
            start_line=row.start_line,
            end_line=row.end_line,
            snippet=row.snippet,
        ),
        cwe_ids=tuple(row.cwe_ids or []),
        mois_id=row.mois_id,
        category=row.category,
        language=row.language,
        finding_id=str(row.id),
        raw=dict(row.raw or {}),
    )
    if row.triage is not None:
        dom.triage = triage_to_domain(row.triage)
    return dom


def triage_to_orm(result: TriageResult) -> models.TriageRecord:
    return models.TriageRecord(
        verdict=result.verdict,
        fp_probability=result.fp_probability,
        rationale=result.rationale,
        recommended_fix=result.recommended_fix,
        patched_code=result.patched_code,
        model=result.model,
    )


def apply_triage(row: models.Finding, result: TriageResult) -> None:
    """기존 행의 triage 를 갱신하거나 새로 만든다."""

    if row.triage is None:
        row.triage = triage_to_orm(result)
        row.triage.finding_id = row.id
        return
    row.triage.verdict = result.verdict
    row.triage.fp_probability = result.fp_probability
    row.triage.rationale = result.rationale
    row.triage.recommended_fix = result.recommended_fix
    row.triage.patched_code = result.patched_code
    row.triage.model = result.model


def triage_to_domain(record: models.TriageRecord) -> TriageResult:
    return TriageResult(
        verdict=record.verdict,
        fp_probability=record.fp_probability,
        rationale=record.rationale,
        recommended_fix=record.recommended_fix,
        patched_code=record.patched_code,
        model=record.model,
    )
