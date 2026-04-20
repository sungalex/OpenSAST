"""CI/CD 빌드 게이트 라우트 — GateService 위임."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from opensast.api.deps import get_current_user, get_db
from opensast.api.schemas import (
    GateCheckRequest,
    GateCheckResult,
    GatePolicyIn,
    GatePolicyOut,
)
from opensast.db import models
from opensast.services import ActorContext, GateService, ServiceError

router = APIRouter(prefix="/api/gate", tags=["gate"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user, ip=request.client.host if request.client else None
    )


@router.put("/policy", response_model=GatePolicyOut)
def upsert_policy(
    payload: GatePolicyIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> GatePolicyOut:
    svc = GateService(db, _actor(request, user))
    try:
        row = svc.upsert_policy(
            project_id=payload.project_id,
            max_high=payload.max_high,
            max_medium=payload.max_medium,
            max_low=payload.max_low,
            max_new_high=payload.max_new_high,
            block_on_triage_fp_below=payload.block_on_triage_fp_below,
            enabled=payload.enabled,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return GatePolicyOut.model_validate(row)


@router.get("/policy/{project_id}", response_model=GatePolicyOut)
def get_policy(
    project_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> GatePolicyOut:
    try:
        row = GateService(db).get_policy(project_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return GatePolicyOut.model_validate(row)


@router.post("/check", response_model=GateCheckResult)
def check_gate(
    payload: GateCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> GateCheckResult:
    svc = GateService(db, _actor(request, user))
    try:
        result = svc.check(
            project_id=payload.project_id,
            scan_id=payload.scan_id,
            base_scan_id=payload.base_scan_id,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return GateCheckResult(**result)
