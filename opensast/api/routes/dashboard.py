"""대시보드 통계 엔드포인트.

상용 솔루션 의 '대시보드' 페이지와 동일한 역할 — 전체 데이터 카드, 체커 분류별 파이
차트, 분석 추이 시계열, TOP 룰 테이블을 프론트에 제공한다.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from opensast.api.deps import get_current_user, get_db
from opensast.db import models
from opensast.mois.catalog import MOIS_ITEMS_BY_ID

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> dict:
    total_projects = db.scalar(select(func.count(models.Project.id))) or 0
    total_scans = db.scalar(select(func.count(models.Scan.id))) or 0
    total_findings = db.scalar(select(func.count(models.Finding.id))) or 0
    sev_rows = db.execute(
        select(models.Finding.severity, func.count(models.Finding.id)).group_by(
            models.Finding.severity
        )
    ).all()
    severity_counts = {s or "UNKNOWN": int(c) for s, c in sev_rows}

    status_rows = db.execute(
        select(models.Finding.status, func.count(models.Finding.id)).group_by(
            models.Finding.status
        )
    ).all()
    status_counts = {s or "new": int(c) for s, c in status_rows}

    latest_scan = db.scalar(
        select(models.Scan).order_by(models.Scan.created_at.desc()).limit(1)
    )
    latest = None
    if latest_scan is not None:
        latest = {
            "id": latest_scan.id,
            "project_id": latest_scan.project_id,
            "status": latest_scan.status,
            "created_at": latest_scan.created_at.isoformat()
            if latest_scan.created_at
            else None,
        }
    return {
        "totals": {
            "projects": total_projects,
            "scans": total_scans,
            "findings": total_findings,
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
        },
        "status_counts": status_counts,
        "latest_scan": latest,
    }


@router.get("/trends")
def trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        select(models.Scan.created_at, models.Scan.engine_stats)
        .where(models.Scan.created_at >= since)
        .order_by(models.Scan.created_at.asc())
    ).all()
    by_day: dict[str, dict[str, int]] = {}
    for created_at, engine_stats in rows:
        if created_at is None:
            continue
        day = created_at.strftime("%Y-%m-%d")
        bucket = by_day.setdefault(day, {"scans": 0, "findings": 0})
        bucket["scans"] += 1
        bucket["findings"] += sum((engine_stats or {}).values())
    timeline = [{"date": d, **v} for d, v in sorted(by_day.items())]
    return {"days": days, "timeline": timeline}


@router.get("/top-rules")
def top_rules(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> dict:
    rows = db.execute(
        select(
            models.Finding.rule_id,
            models.Finding.engine,
            func.count(models.Finding.id).label("cnt"),
        )
        .group_by(models.Finding.rule_id, models.Finding.engine)
        .order_by(func.count(models.Finding.id).desc())
        .limit(limit)
    ).all()
    return {
        "top": [
            {"rule_id": r, "engine": e, "count": int(c)} for r, e, c in rows
        ]
    }


@router.get("/mois-coverage")
def mois_coverage(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> dict:
    rows = db.execute(
        select(models.Finding.mois_id, func.count(models.Finding.id))
        .group_by(models.Finding.mois_id)
    ).all()
    counts: dict[str, int] = {mid or "unknown": int(c) for mid, c in rows}
    items = []
    covered = 0
    for item_id, item in MOIS_ITEMS_BY_ID.items():
        cnt = counts.get(item_id, 0)
        if cnt > 0:
            covered += 1
        items.append(
            {
                "mois_id": item_id,
                "name_kr": item.name_kr,
                "category": item.category.value,
                "severity": item.severity.value,
                "count": cnt,
                "covered": cnt > 0,
            }
        )
    return {
        "total_items": len(items),
        "covered_items": covered,
        "coverage_ratio": round(covered / len(items), 3) if items else 0.0,
        "items": items,
    }


@router.get("/category-distribution")
def category_distribution(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> dict:
    rows = db.execute(
        select(models.Finding.category, func.count(models.Finding.id))
        .where(models.Finding.category.is_not(None))
        .group_by(models.Finding.category)
    ).all()
    return {"categories": [{"name": c, "count": int(n)} for c, n in rows]}
