"""프로젝트 탐지 제외 규칙 라우트 — SuppressionService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from opensast.api.deps import ROLE_ADMIN, get_actor, get_db, require_actor
from opensast.api.schemas import SuppressionCreate, SuppressionOut
from opensast.services import ActorContext, ServiceError, SuppressionService

router = APIRouter(prefix="/api/projects", tags=["suppressions"])


@router.get("/{project_id}/suppressions", response_model=list[SuppressionOut])
def list_suppressions(
    project_id: int,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> list[SuppressionOut]:
    rows = SuppressionService(db, actor).list_for_project(project_id)
    return [SuppressionOut.model_validate(r) for r in rows]


@router.post(
    "/{project_id}/suppressions",
    response_model=SuppressionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_suppression(
    project_id: int,
    payload: SuppressionCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> SuppressionOut:
    svc = SuppressionService(db, actor)
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
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> None:
    svc = SuppressionService(db, actor)
    try:
        svc.delete(project_id=project_id, suppression_id=suppression_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
