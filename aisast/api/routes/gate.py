"""CI/CD 빌드 게이트(이관 제어) 라우트.

Sparrow 의 '이관 제어' 에 해당. 프로젝트별 임계값 정책을 DB에 저장하고, 최신
스캔 결과가 임계값을 초과하면 게이트가 실패를 반환한다. CI 파이프라인은 HTTP
상태코드 또는 응답 `passed` 필드로 머지/배포를 차단할 수 있다.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db, require_role
from aisast.api.schemas import (
    GateCheckRequest,
    GateCheckResult,
    GatePolicyIn,
    GatePolicyOut,
)
from aisast.db import models

router = APIRouter(prefix="/api/gate", tags=["gate"])


@router.put(
    "/policy",
    response_model=GatePolicyOut,
    dependencies=[Depends(require_role("admin"))],
)
def upsert_policy(
    payload: GatePolicyIn,
    db: Session = Depends(get_db),
) -> GatePolicyOut:
    existing = db.scalar(
        select(models.GatePolicy).where(
            models.GatePolicy.project_id == payload.project_id
        )
    )
    if existing:
        for field in (
            "max_high",
            "max_medium",
            "max_low",
            "max_new_high",
            "block_on_triage_fp_below",
            "enabled",
        ):
            setattr(existing, field, getattr(payload, field))
        db.commit()
        db.refresh(existing)
        return GatePolicyOut.model_validate(existing)
    row = models.GatePolicy(
        project_id=payload.project_id,
        max_high=payload.max_high,
        max_medium=payload.max_medium,
        max_low=payload.max_low,
        max_new_high=payload.max_new_high,
        block_on_triage_fp_below=payload.block_on_triage_fp_below,
        enabled=payload.enabled,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return GatePolicyOut.model_validate(row)


@router.get("/policy/{project_id}", response_model=GatePolicyOut)
def get_policy(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> GatePolicyOut:
    row = db.scalar(
        select(models.GatePolicy).where(models.GatePolicy.project_id == project_id)
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no policy")
    return GatePolicyOut.model_validate(row)


@router.post("/check", response_model=GateCheckResult)
def check_gate(
    payload: GateCheckRequest,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> GateCheckResult:
    policy = db.scalar(
        select(models.GatePolicy).where(
            models.GatePolicy.project_id == payload.project_id
        )
    )
    if policy is None or not policy.enabled:
        return GateCheckResult(passed=True, reasons=["no policy / disabled"], counts={})

    # 대상 스캔 결정
    if payload.scan_id:
        scan = db.get(models.Scan, payload.scan_id)
    else:
        scan = db.scalar(
            select(models.Scan)
            .where(
                models.Scan.project_id == payload.project_id,
                models.Scan.status == "completed",
            )
            .order_by(models.Scan.created_at.desc())
            .limit(1)
        )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no completed scan to check"
        )

    findings = list(
        db.scalars(
            select(models.Finding).where(
                models.Finding.scan_id == scan.id,
                models.Finding.status != "excluded",
            )
        )
    )
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    reasons: list[str] = []
    if counts["HIGH"] > policy.max_high:
        reasons.append(f"HIGH {counts['HIGH']} > 임계값 {policy.max_high}")
    if counts["MEDIUM"] > policy.max_medium:
        reasons.append(f"MEDIUM {counts['MEDIUM']} > 임계값 {policy.max_medium}")
    if counts["LOW"] > policy.max_low:
        reasons.append(f"LOW {counts['LOW']} > 임계값 {policy.max_low}")

    # 신규 HIGH 비교 (base_scan_id 제공 시)
    new_high = 0
    if payload.base_scan_id:
        base_hashes = {
            r.finding_hash
            for r in db.scalars(
                select(models.Finding).where(
                    models.Finding.scan_id == payload.base_scan_id
                )
            )
        }
        new_high = sum(
            1
            for f in findings
            if f.severity == "HIGH" and f.finding_hash not in base_hashes
        )
        if new_high > policy.max_new_high:
            reasons.append(
                f"신규 HIGH {new_high} > 임계값 {policy.max_new_high}"
            )

    passed = not reasons
    return GateCheckResult(
        passed=passed,
        reasons=reasons if reasons else ["within thresholds"],
        counts=counts,
        new_high=new_high,
    )
