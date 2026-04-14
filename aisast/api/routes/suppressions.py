"""프로젝트 단위 탐지 제외 규칙 관리."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import SuppressionCreate, SuppressionOut
from aisast.db import models, repo

router = APIRouter(prefix="/api/projects", tags=["suppressions"])


@router.get("/{project_id}/suppressions", response_model=list[SuppressionOut])
def list_suppressions(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[SuppressionOut]:
    rows = list(
        db.scalars(
            select(models.SuppressionRule).where(
                models.SuppressionRule.project_id == project_id
            )
        )
    )
    return [SuppressionOut.model_validate(r) for r in rows]


@router.post(
    "/{project_id}/suppressions",
    response_model=SuppressionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_suppression(
    project_id: int,
    payload: SuppressionCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> SuppressionOut:
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    row = models.SuppressionRule(
        project_id=project_id,
        kind=payload.kind,
        pattern=payload.pattern,
        rule_id=payload.rule_id,
        reason=payload.reason,
        created_by=user.id,
    )
    db.add(row)
    repo.record_audit(
        db,
        user_id=user.id,
        action="suppression.create",
        target_type="project",
        target_id=str(project_id),
        detail={"kind": payload.kind, "pattern": payload.pattern, "rule_id": payload.rule_id},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(row)
    return SuppressionOut.model_validate(row)


@router.delete(
    "/{project_id}/suppressions/{suppression_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_suppression(
    project_id: int,
    suppression_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> None:
    row = db.get(models.SuppressionRule, suppression_id)
    if row is None or row.project_id != project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    db.delete(row)
    repo.record_audit(
        db,
        user_id=user.id,
        action="suppression.delete",
        target_type="project",
        target_id=str(project_id),
        detail={"id": suppression_id},
        ip=request.client.host if request.client else None,
    )
    db.commit()
