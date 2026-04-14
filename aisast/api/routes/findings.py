"""Finding 조회 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import FindingOut
from aisast.db import models, repo

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/scan/{scan_id}", response_model=list[FindingOut])
def list_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[FindingOut]:
    rows = repo.list_findings_for_scan(db, scan_id)
    return [FindingOut.model_validate(r) for r in rows]


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> FindingOut:
    row = db.get(models.Finding, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return FindingOut.model_validate(row)
