"""대시보드 집계 서비스.

대시보드는 원래 라우트가 ORM 을 직접 호출해 조직 스코핑을 완전히 우회했다
(진단 C-2). 집계도 다른 조회와 같은 서비스 계층을 지나도록 옮겨, 조직 필터가
한 곳에서만 정의되게 한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, func, select

from opensast.db import models
from opensast.mois.catalog import MOIS_ITEMS_BY_ID
from opensast.services.base import BaseService


class DashboardService(BaseService):
    # ---- 스코핑 헬퍼 ----------------------------------------------------
    def _scoped_projects(self) -> Select:
        return select(models.Project.id).where(self._org_filter(models.Project))

    def _scoped_scans(self) -> Select:
        return select(models.Scan.id).where(
            models.Scan.project_id.in_(self._scoped_projects())
        )

    def _finding_scope(self):
        """Finding 을 조직 범위로 제한하는 WHERE 절."""

        return models.Finding.scan_id.in_(self._scoped_scans())

    # ---- 집계 -----------------------------------------------------------
    def overview(self) -> dict:
        scoped_projects = self._scoped_projects()
        scoped_scans = self._scoped_scans()
        finding_scope = self._finding_scope()

        total_projects = (
            self.session.scalar(
                select(func.count()).select_from(scoped_projects.subquery())
            )
            or 0
        )
        total_scans = (
            self.session.scalar(
                select(func.count()).select_from(scoped_scans.subquery())
            )
            or 0
        )
        total_findings = (
            self.session.scalar(
                select(func.count(models.Finding.id)).where(finding_scope)
            )
            or 0
        )
        sev_rows = self.session.execute(
            select(models.Finding.severity, func.count(models.Finding.id))
            .where(finding_scope)
            .group_by(models.Finding.severity)
        ).all()
        severity_counts = {s or "UNKNOWN": int(c) for s, c in sev_rows}

        status_rows = self.session.execute(
            select(models.Finding.status, func.count(models.Finding.id))
            .where(finding_scope)
            .group_by(models.Finding.status)
        ).all()
        status_counts = {s or "new": int(c) for s, c in status_rows}

        latest_scan = self.session.scalar(
            select(models.Scan)
            .where(models.Scan.project_id.in_(self._scoped_projects()))
            .order_by(models.Scan.created_at.desc())
            .limit(1)
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

    def trends(self, *, days: int = 30) -> dict:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        rows = self.session.execute(
            select(models.Scan.created_at, models.Scan.engine_stats)
            .where(
                models.Scan.created_at >= since,
                models.Scan.project_id.in_(self._scoped_projects()),
            )
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

    def top_rules(self, *, limit: int = 10) -> dict:
        rows = self.session.execute(
            select(
                models.Finding.rule_id,
                models.Finding.engine,
                func.count(models.Finding.id).label("cnt"),
            )
            .where(self._finding_scope())
            .group_by(models.Finding.rule_id, models.Finding.engine)
            .order_by(func.count(models.Finding.id).desc())
            .limit(limit)
        ).all()
        return {
            "top": [
                {"rule_id": r, "engine": e, "count": int(c)} for r, e, c in rows
            ]
        }

    def mois_coverage(self) -> dict:
        rows = self.session.execute(
            select(models.Finding.mois_id, func.count(models.Finding.id))
            .where(self._finding_scope())
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

    def category_distribution(self) -> dict:
        rows = self.session.execute(
            select(models.Finding.category, func.count(models.Finding.id))
            .where(
                models.Finding.category.is_not(None),
                self._finding_scope(),
            )
            .group_by(models.Finding.category)
        ).all()
        return {"categories": [{"name": c, "count": int(n)} for c, n in rows]}
