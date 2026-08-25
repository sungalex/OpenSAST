"""대시보드 통계 엔드포인트 — DashboardService 위임.

집계도 다른 조회와 동일하게 서비스 계층을 지나며, 따라서 동일한 조직 스코핑을
적용받는다 (ADR-0005).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from opensast.api.deps import get_actor, get_db
from opensast.services import ActorContext, DashboardService

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    return DashboardService(db, actor).overview()


@router.get("/trends")
def trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    return DashboardService(db, actor).trends(days=days)


@router.get("/top-rules")
def top_rules(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    return DashboardService(db, actor).top_rules(limit=limit)


@router.get("/mois-coverage")
def mois_coverage(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    return DashboardService(db, actor).mois_coverage()


@router.get("/category-distribution")
def category_distribution(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    return DashboardService(db, actor).category_distribution()
