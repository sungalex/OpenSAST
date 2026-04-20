"""감사 로그 조회 API (admin 전용)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from opensast.api.deps import get_db, require_role
from opensast.api.schemas import AuditLogOut
from opensast.db import models

router = APIRouter(
    prefix="/api/admin/audit",
    tags=["audit"],
    dependencies=[Depends(require_role("admin"))],
)


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    action: str | None = Query(None),
    user_id: int | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[AuditLogOut]:
    stmt = select(models.AuditLog).order_by(models.AuditLog.created_at.desc())
    if action:
        stmt = stmt.where(models.AuditLog.action == action)
    if user_id is not None:
        stmt = stmt.where(models.AuditLog.user_id == user_id)
    stmt = stmt.offset(offset).limit(limit)
    rows = list(db.scalars(stmt))
    return [AuditLogOut.model_validate(r) for r in rows]
