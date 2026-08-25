"""체커 그룹(RuleSet) 라우트 — RuleSetService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from opensast.api.deps import ROLE_ADMIN, get_actor, get_db, require_actor
from opensast.api.schemas import RuleSetCreate, RuleSetOut
from opensast.services import ActorContext, RuleSetService, ServiceError

router = APIRouter(prefix="/api/rule-sets", tags=["rule-sets"])


@router.get("", response_model=list[RuleSetOut])
def list_rule_sets(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> list[RuleSetOut]:
    rows = RuleSetService(db, actor).list_all()
    return [RuleSetOut.model_validate(r) for r in rows]


@router.post("", response_model=RuleSetOut, status_code=status.HTTP_201_CREATED)
def create_rule_set(
    payload: RuleSetCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> RuleSetOut:
    svc = RuleSetService(db, actor)
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
    actor: ActorContext = Depends(get_actor),
) -> RuleSetOut:
    try:
        row = RuleSetService(db, actor).get(rule_set_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return RuleSetOut.model_validate(row)


@router.delete("/{rule_set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule_set(
    rule_set_id: int,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> None:
    svc = RuleSetService(db, actor)
    try:
        svc.delete(rule_set_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
