"""체커 그룹(RuleSet) 관리 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db, require_role
from aisast.api.schemas import RuleSetCreate, RuleSetOut
from aisast.db import models

router = APIRouter(prefix="/api/rule-sets", tags=["rule-sets"])


@router.get("", response_model=list[RuleSetOut])
def list_rule_sets(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[RuleSetOut]:
    rows = list(db.scalars(select(models.RuleSet).order_by(models.RuleSet.id)))
    return [RuleSetOut.model_validate(r) for r in rows]


@router.post(
    "",
    response_model=RuleSetOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
def create_rule_set(
    payload: RuleSetCreate,
    db: Session = Depends(get_db),
) -> RuleSetOut:
    if db.scalar(
        select(models.RuleSet).where(models.RuleSet.name == payload.name)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="rule set name exists"
        )
    row = models.RuleSet(
        name=payload.name,
        description=payload.description,
        enabled_engines=payload.enabled_engines,
        include_rules=payload.include_rules,
        exclude_rules=payload.exclude_rules,
        min_severity=payload.min_severity.upper(),
        is_default=payload.is_default,
    )
    if payload.is_default:
        for existing in db.scalars(
            select(models.RuleSet).where(models.RuleSet.is_default.is_(True))
        ):
            existing.is_default = False
    db.add(row)
    db.commit()
    db.refresh(row)
    return RuleSetOut.model_validate(row)


@router.get("/{rule_set_id}", response_model=RuleSetOut)
def get_rule_set(
    rule_set_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> RuleSetOut:
    row = db.get(models.RuleSet, rule_set_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return RuleSetOut.model_validate(row)


@router.delete(
    "/{rule_set_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
def delete_rule_set(
    rule_set_id: int,
    db: Session = Depends(get_db),
) -> None:
    row = db.get(models.RuleSet, rule_set_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if row.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cannot delete default rule set",
        )
    db.delete(row)
    db.commit()
