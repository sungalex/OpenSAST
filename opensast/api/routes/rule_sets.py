"""체커 그룹(RuleSet) 라우트 — RuleSetService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from opensast.api.deps import get_current_user, get_db
from opensast.api.schemas import RuleSetCreate, RuleSetOut
from opensast.db import models
from opensast.services import ActorContext, RuleSetService, ServiceError

router = APIRouter(prefix="/api/rule-sets", tags=["rule-sets"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user, ip=request.client.host if request.client else None
    )


@router.get("", response_model=list[RuleSetOut])
def list_rule_sets(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[RuleSetOut]:
    rows = RuleSetService(db).list_all()
    return [RuleSetOut.model_validate(r) for r in rows]


@router.post("", response_model=RuleSetOut, status_code=status.HTTP_201_CREATED)
def create_rule_set(
    payload: RuleSetCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> RuleSetOut:
    svc = RuleSetService(db, _actor(request, user))
    try:
        row = svc.create(
            name=payload.name,
            description=payload.description,
            enabled_engines=payload.enabled_engines,
            include_rules=payload.include_rules,
            exclude_rules=payload.exclude_rules,
            min_severity=payload.min_severity,
            is_default=payload.is_default,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return RuleSetOut.model_validate(row)


@router.get("/{rule_set_id}", response_model=RuleSetOut)
def get_rule_set(
    rule_set_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> RuleSetOut:
    try:
        row = RuleSetService(db).get(rule_set_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return RuleSetOut.model_validate(row)


@router.delete("/{rule_set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_set(
    rule_set_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> None:
    svc = RuleSetService(db, _actor(request, user))
    try:
        svc.delete(rule_set_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
