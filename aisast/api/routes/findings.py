"""Findings 라우트 — FindingService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import (
    FindingOut,
    FindingStatusUpdate,
    NlQuery,
    ReferenceOut,
    TriageOut,
)
from aisast.db import models
from aisast.mois.references import references_for_cwes
from aisast.services import ActorContext, FindingService, ServiceError

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


# ---------------------------------------------------------------------------
# 조회
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}", response_model=list[FindingOut])
def list_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    rows = FindingService(db).for_scan(scan_id)
    return [_finding_to_out(r) for r in rows]


# ---------------------------------------------------------------------------
# Advanced Issue Filter — /{finding_id} 보다 먼저 선언
# ---------------------------------------------------------------------------


@router.get("/search", response_model=list[FindingOut])
def search_findings(
    scan_id: str | None = Query(None),
    project_id: int | None = Query(None),
    severity: list[str] | None = Query(None),
    engine: list[str] | None = Query(None),
    statuses: list[str] | None = Query(None, alias="status"),
    mois_id: list[str] | None = Query(None),
    cwe: list[str] | None = Query(None),
    path_glob: str | None = Query(None),
    text: str | None = Query(None),
    include_excluded: bool = Query(False),
    cursor: str | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    rows = FindingService(db).search(
        scan_id=scan_id,
        project_id=project_id,
        severity=severity,
        engines=engine,
        statuses=statuses,
        mois_ids=mois_id,
        cwe_ids=cwe,
        path_glob=path_glob,
        text=text,
        include_excluded=include_excluded,
        cursor=cursor,
        limit=limit,
        offset=offset,
    )
    return [_finding_to_out(r) for r in rows]


# ---------------------------------------------------------------------------
# 워크플로 상태 전이 — /{finding_id}/status
# ---------------------------------------------------------------------------


@router.post("/{finding_id}/status", response_model=FindingOut)
def update_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> FindingOut:
    svc = FindingService(db, _actor(request, user))
    try:
        row = svc.change_status(
            finding_id, new_status=payload.status, reason=payload.reason
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return _finding_to_out(row)


# ---------------------------------------------------------------------------
# LLM 자연어 이슈 검색
# ---------------------------------------------------------------------------


@router.post("/ask", response_model=list[FindingOut])
def natural_language_search(
    payload: NlQuery,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    import json
    import re

    from aisast.llm.base import LLMError
    from aisast.llm.triage import build_client

    client = build_client()
    system = (
        "당신은 한국어 보안 진단 어시스턴트입니다. 사용자 질의를 다음 JSON 스키마로 "
        "변환하세요. 알 수 없는 필드는 생략합니다:\n"
        '{ "severity": ["HIGH"|"MEDIUM"|"LOW"], "engines": [], "mois_ids": [], '
        '"cwe_ids": [], "text": "...", "statuses": [] }\n'
        "반드시 JSON 객체 하나만 반환합니다."
    )
    try:
        resp = client.complete(system, f"질의: {payload.query}")
        match = re.search(r"\{[\s\S]*\}", resp.text)
        parsed = json.loads(match.group(0)) if match else {}
    except (LLMError, Exception):  # noqa: BLE001
        parsed = _keyword_fallback(payload.query)

    rows = FindingService(db).search(
        scan_id=payload.scan_id,
        project_id=payload.project_id,
        severity=parsed.get("severity"),
        engines=parsed.get("engines"),
        statuses=parsed.get("statuses"),
        mois_ids=parsed.get("mois_ids"),
        cwe_ids=parsed.get("cwe_ids"),
        text=parsed.get("text"),
        limit=200,
    )
    return [_finding_to_out(r) for r in rows]


# 정수 path param — 마지막에 선언
@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> FindingOut:
    try:
        row = FindingService(db).get(finding_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return _finding_to_out(row)


def _keyword_fallback(query: str) -> dict:
    q = query.lower()
    out: dict = {"text": query}
    if "high" in q or "고위" in q or "심각" in q:
        out["severity"] = ["HIGH"]
    elif "medium" in q or "중간" in q:
        out["severity"] = ["MEDIUM"]
    elif "low" in q:
        out["severity"] = ["LOW"]
    if "sql" in q:
        out["mois_ids"] = ["SR1-1"]
    if "xss" in q:
        out["mois_ids"] = ["SR1-3"]
    if "ssrf" in q:
        out["mois_ids"] = ["SR1-11"]
    return out


def _finding_to_out(row: models.Finding) -> FindingOut:
    refs = references_for_cwes(row.cwe_ids or [])
    triage = TriageOut.model_validate(row.triage) if row.triage is not None else None
    return FindingOut(
        id=row.id,
        scan_id=row.scan_id,
        rule_id=row.rule_id,
        engine=row.engine,
        severity=row.severity,
        message=row.message,
        file_path=row.file_path,
        start_line=row.start_line,
        end_line=row.end_line,
        cwe_ids=list(row.cwe_ids or []),
        mois_id=row.mois_id,
        category=row.category,
        language=row.language,
        snippet=row.snippet,
        status=row.status or "new",
        status_reason=row.status_reason,
        reviewed_by=row.reviewed_by,
        triage=triage,
        references=[ReferenceOut(**r.as_dict()) for r in refs],
    )
