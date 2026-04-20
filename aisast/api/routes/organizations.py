"""조직 관리 API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aisast.api.deps import get_db, require_role
from aisast.db import models

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


@router.post("", status_code=201)
def create_org(
    payload: dict,
    db: Session = Depends(get_db),
    user=Depends(require_role("admin")),
):
    if db.scalar(
        select(models.Organization).where(
            models.Organization.slug == payload["slug"]
        )
    ):
        raise HTTPException(status_code=409, detail="slug already exists")
    org = models.Organization(
        slug=payload["slug"], name=payload["name"], is_active=True
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return {
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "is_active": org.is_active,
    }


@router.get("")
def list_orgs(db: Session = Depends(get_db)):
    orgs = list(
        db.scalars(select(models.Organization).order_by(models.Organization.id))
    )
    return [
        {"id": o.id, "slug": o.slug, "name": o.name, "is_active": o.is_active}
        for o in orgs
    ]


@router.get("/{org_id}")
def get_org(org_id: int, db: Session = Depends(get_db)):
    org = db.get(models.Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    return {
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "is_active": org.is_active,
    }
