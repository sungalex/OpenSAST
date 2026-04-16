"""Finding 조회·상태 전이·필터·자연어 검색 서비스."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Iterable

from fastapi import status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from aisast.db import models, repo
from aisast.hooks import hook_registry
from aisast.mois.references import references_for_cwes
from aisast.services.base import BaseService, ServiceError


_SELF_TRANSITIONS: dict[str, set[str]] = {
    "new": {"confirmed", "exclusion_requested", "fixed"},
    "confirmed": {"exclusion_requested", "fixed", "new"},
    "exclusion_requested": {"new"},
    "fixed": {"new", "confirmed"},
    "rejected": {"new"},
}
_ADMIN_TRANSITIONS: dict[str, set[str]] = {
    "exclusion_requested": {"excluded", "rejected", "new"},
    "excluded": {"new"},
    "confirmed": {"excluded"},
    "new": {"excluded"},
}


class FindingService(BaseService):
    # ---- 조회 --------------------------------------------------------
    def for_scan(self, scan_id: str) -> list[models.Finding]:
        return repo.list_findings_for_scan(self.session, scan_id)

    def get(self, finding_id: int) -> models.Finding:
        row = self.session.get(models.Finding, finding_id)
        if row is None:
            raise ServiceError("finding not found", status_code=status.HTTP_404_NOT_FOUND)
        return row

    # ---- 검색 --------------------------------------------------------
    def search(
        self,
        *,
        scan_id: str | None = None,
        project_id: int | None = None,
        severity: Iterable[str] | None = None,
        engines: Iterable[str] | None = None,
        statuses: Iterable[str] | None = None,
        mois_ids: Iterable[str] | None = None,
        cwe_ids: Iterable[str] | None = None,
        path_glob: str | None = None,
        text: str | None = None,
        include_excluded: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[models.Finding]:
        # cwe_ids와 path_glob 필터가 있으면 DB에서 더 많이 가져와 메모리 필터 후 잘라냄
        fetch_limit = limit * 3 if (cwe_ids or path_glob) else limit

        stmt = select(models.Finding).options(
            selectinload(models.Finding.triage)
        )
        filters = []
        if scan_id:
            filters.append(models.Finding.scan_id == scan_id)
        if project_id is not None:
            stmt = stmt.join(models.Scan)
            filters.append(models.Scan.project_id == project_id)
        if severity:
            filters.append(
                models.Finding.severity.in_([s.upper() for s in severity])
            )
        if engines:
            filters.append(models.Finding.engine.in_(list(engines)))
        if statuses:
            filters.append(models.Finding.status.in_(list(statuses)))
        elif not include_excluded:
            filters.append(models.Finding.status != "excluded")
        if mois_ids:
            filters.append(models.Finding.mois_id.in_(list(mois_ids)))
        if text:
            like = f"%{text}%"
            filters.append(
                or_(
                    models.Finding.message.ilike(like),
                    models.Finding.rule_id.ilike(like),
                    models.Finding.file_path.ilike(like),
                )
            )
        if filters:
            stmt = stmt.where(and_(*filters))
        stmt = (
            stmt.order_by(
                models.Finding.severity.asc(),
                models.Finding.created_at.desc(),
            )
            .offset(offset)
            .limit(fetch_limit)
        )
        rows = list(self.session.scalars(stmt))
        if cwe_ids:
            wanted = {c.upper() for c in cwe_ids}
            rows = [
                r for r in rows if wanted.intersection(map(str.upper, r.cwe_ids or []))
            ]
        if path_glob:
            rows = [r for r in rows if fnmatch.fnmatch(r.file_path, path_glob)]
        return rows[:limit]

    # ---- 상태 전이 ---------------------------------------------------
    def change_status(
        self, finding_id: int, *, new_status: str, reason: str | None
    ) -> models.Finding:
        row = self.get(finding_id)
        current = row.status or "new"
        allowed_self = _SELF_TRANSITIONS.get(current, set())
        allowed_admin = (
            _ADMIN_TRANSITIONS.get(current, set())
            if self.actor.role == "admin"
            else set()
        )
        if new_status not in (allowed_self | allowed_admin):
            raise ServiceError(
                f"상태 '{current}' → '{new_status}' 전이 허용되지 않음 "
                f"(role={self.actor.role})",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        old_status = current
        row.status = new_status
        row.status_reason = reason
        row.reviewed_by = self.actor.user_id
        row.reviewed_at = datetime.now(timezone.utc)
        self._audit(
            "finding.status_change",
            target_type="finding",
            target_id=row.id,
            detail={
                "from": old_status,
                "to": new_status,
                "reason": reason or "",
                "scan_id": row.scan_id,
                "rule_id": row.rule_id,
            },
        )

        # 훅 발행 — 코어 외 확장 포인트
        for plugin in hook_registry.all():
            handler = getattr(plugin.factory, "on_status_change", None)
            if callable(handler):
                try:
                    handler(row, old_status, new_status)
                except Exception as exc:  # noqa: BLE001
                    self._audit(
                        "hook.error",
                        detail={"hook": plugin.name, "error": str(exc)},
                    )

        self.session.commit()
        self.session.refresh(row)
        return row

    # ---- 응답 직렬화 도우미 -----------------------------------------
    @staticmethod
    def attach_references(row: models.Finding) -> list[dict]:
        return [t.as_dict() for t in references_for_cwes(row.cwe_ids or [])]
