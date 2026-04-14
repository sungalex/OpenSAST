"""Finding 조회·상태 전이·Advanced Filter 라우트."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import (
    FindingOut,
    FindingStatusUpdate,
    NlQuery,
    ReferenceOut,
)
from aisast.db import models, repo
from aisast.mois.references import references_for_cwes

router = APIRouter(prefix="/api/findings", tags=["findings"])


# ---------------------------------------------------------------------------
# 조회
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}", response_model=list[FindingOut])
def list_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    rows = repo.list_findings_for_scan(db, scan_id)
    return [_finding_to_out(r) for r in rows]


# ---------------------------------------------------------------------------
# Advanced Issue Filter — Sparrow 의 Advanced Issue Filter 대응
# /search, /ask, /{id}/status 는 정수 path param `/{finding_id}` 보다 먼저
# 선언하여 라우팅 우선순위를 보장한다.
# ---------------------------------------------------------------------------


@router.get("/search", response_model=list[FindingOut])
def search_findings(
    request: Request,
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
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    """다중 필터로 이슈 검색."""

    stmt = select(models.Finding)
    filters = []
    if scan_id:
        filters.append(models.Finding.scan_id == scan_id)
    if project_id is not None:
        stmt = stmt.join(models.Scan)
        filters.append(models.Scan.project_id == project_id)
    if severity:
        filters.append(models.Finding.severity.in_([s.upper() for s in severity]))
    if engine:
        filters.append(models.Finding.engine.in_(engine))
    if statuses:
        filters.append(models.Finding.status.in_(statuses))
    elif not include_excluded:
        filters.append(models.Finding.status != "excluded")
    if mois_id:
        filters.append(models.Finding.mois_id.in_(mois_id))
    if cwe:
        # JSON array contains — DB 밴더 독립성을 위해 Python 측에서 재필터링
        pass
    if text:
        like = f"%{text}%"
        filters.append(
            or_(
                models.Finding.message.ilike(like),
                models.Finding.rule_id.ilike(like),
                models.Finding.file_path.ilike(like),
            )
        )
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(
        models.Finding.severity.asc(),
        models.Finding.created_at.desc(),
    ).offset(offset).limit(limit)
    rows = list(db.scalars(stmt))
    if cwe:
        wanted = {c.upper() for c in cwe}
        rows = [r for r in rows if wanted.intersection(map(str.upper, r.cwe_ids or []))]
    if path_glob:
        rows = [r for r in rows if fnmatch.fnmatch(r.file_path, path_glob)]
    return [_finding_to_out(r) for r in rows]


# ---------------------------------------------------------------------------
# 상태 전이 — 미확인/확인/제외신청/제외승인/수정완료
# ---------------------------------------------------------------------------


_ALLOWED_SELF_TRANSITIONS = {
    "new": {"confirmed", "exclusion_requested", "fixed"},
    "confirmed": {"exclusion_requested", "fixed", "new"},
    "exclusion_requested": {"new"},  # 취소
    "fixed": {"new", "confirmed"},
    "rejected": {"new"},
}
_ADMIN_TRANSITIONS = {
    "exclusion_requested": {"excluded", "rejected", "new"},
    "excluded": {"new"},
    "confirmed": {"excluded"},
    "new": {"excluded"},
}


@router.post("/{finding_id}/status", response_model=FindingOut)
def update_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> FindingOut:
    row = db.get(models.Finding, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    current = row.status or "new"
    target = payload.status
    allowed_self = _ALLOWED_SELF_TRANSITIONS.get(current, set())
    allowed_admin = _ADMIN_TRANSITIONS.get(current, set()) if user.role == "admin" else set()
    if target not in (allowed_self | allowed_admin):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"상태 '{current}' → '{target}' 전이 허용되지 않음 "
                f"(role={user.role})"
            ),
        )
    row.status = target
    row.status_reason = payload.reason
    row.reviewed_by = user.id
    row.reviewed_at = datetime.now(timezone.utc)

    repo.record_audit(
        db,
        user_id=user.id,
        action="finding.status_change",
        target_type="finding",
        target_id=str(row.id),
        detail={
            "from": current,
            "to": target,
            "reason": payload.reason or "",
            "scan_id": row.scan_id,
            "rule_id": row.rule_id,
        },
        ip=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(row)
    return _finding_to_out(row)


# ---------------------------------------------------------------------------
# LLM 자연어 질의 검색 (aiSAST 차별화)
# ---------------------------------------------------------------------------


@router.post("/ask", response_model=list[FindingOut])
def natural_language_search(
    payload: NlQuery,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    """한국어 자연어 질의를 필터 구조로 변환해 검색.

    LLM 이 설치되지 않은 환경에서는 간단한 키워드 추출(fallback)만 수행한다.
    """

    from aisast.llm.triage import build_client
    from aisast.llm.base import LLMError
    import json
    import re

    client = build_client()
    system = (
        "당신은 한국어 보안 진단 어시스턴트입니다. 사용자 질의를 다음 JSON 스키마로 "
        "변환하세요. 알 수 없는 필드는 생략합니다:\n"
        '{ "severity": ["HIGH"|"MEDIUM"|"LOW"], "engines": [], "mois_ids": [], '
        '"cwe_ids": [], "text": "...", "statuses": [] }\n'
        "반드시 JSON 객체 하나만 반환합니다."
    )
    user_msg = f"질의: {payload.query}"
    try:
        resp = client.complete(system, user_msg)
        match = re.search(r"\{[\s\S]*\}", resp.text)
        parsed = json.loads(match.group(0)) if match else {}
    except (LLMError, Exception):  # noqa: BLE001
        parsed = _keyword_fallback(payload.query)

    stmt = select(models.Finding)
    if payload.scan_id:
        stmt = stmt.where(models.Finding.scan_id == payload.scan_id)
    if payload.project_id is not None:
        stmt = stmt.join(models.Scan).where(
            models.Scan.project_id == payload.project_id
        )
    if parsed.get("severity"):
        stmt = stmt.where(
            models.Finding.severity.in_([s.upper() for s in parsed["severity"]])
        )
    if parsed.get("engines"):
        stmt = stmt.where(models.Finding.engine.in_(parsed["engines"]))
    if parsed.get("mois_ids"):
        stmt = stmt.where(models.Finding.mois_id.in_(parsed["mois_ids"]))
    if parsed.get("statuses"):
        stmt = stmt.where(models.Finding.status.in_(parsed["statuses"]))
    text = (parsed.get("text") or "").strip()
    if text:
        like = f"%{text}%"
        stmt = stmt.where(
            or_(
                models.Finding.message.ilike(like),
                models.Finding.rule_id.ilike(like),
            )
        )
    stmt = stmt.order_by(models.Finding.severity.asc()).limit(200)
    rows = list(db.scalars(stmt))
    if parsed.get("cwe_ids"):
        wanted = {c.upper() for c in parsed["cwe_ids"]}
        rows = [
            r for r in rows if wanted.intersection(map(str.upper, r.cwe_ids or []))
        ]
    return [_finding_to_out(r) for r in rows]


# 정수 path param 라우트는 모든 정적 path 보다 뒤에 선언
@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> FindingOut:
    row = db.get(models.Finding, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _finding_to_out(row)


def _keyword_fallback(query: str) -> dict:
    """LLM 이 없을 때 사용하는 최소 키워드 파서."""

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


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------


def _finding_to_out(row: models.Finding) -> FindingOut:
    refs = references_for_cwes(row.cwe_ids or [])
    triage = None
    if row.triage is not None:
        from aisast.api.schemas import TriageOut

        triage = TriageOut.model_validate(row.triage)
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
