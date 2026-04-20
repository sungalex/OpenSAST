"""프로젝트 탐지 제외 규칙 라우트 — SuppressionService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from opensast.api.deps import get_current_user, get_db
from opensast.api.schemas import SuppressionCreate, SuppressionOut
from opensast.db import models
from opensast.services import ActorContext, ServiceError, SuppressionService

router = APIRouter(prefix="/api/projects", tags=["suppressions"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user, ip=request.client.host if request.client else None
    )


@router.get("/{project_id}/suppressions", response_model=list[SuppressionOut])
def list_suppressions(
    project_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[SuppressionOut]:
    rows = SuppressionService(db).list_for_project(project_id)
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
    svc = SuppressionService(db, _actor(request, user))
    try:
        row = svc.create(
            project_id=project_id,
            kind=payload.kind,
            pattern=payload.pattern,
            rule_id=payload.rule_id,
            reason=payload.reason,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
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
    svc = SuppressionService(db, _actor(request, user))
    try:
        svc.delete(project_id=project_id, suppression_id=suppression_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
