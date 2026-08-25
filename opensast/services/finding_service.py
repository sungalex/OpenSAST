"""Finding 조회·상태 전이·필터·자연어 검색 서비스."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Iterable

from fastapi import status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from opensast.db import models, repo
from opensast.hooks import hook_registry
from opensast.mois.references import references_for_cwes
from opensast.services.base import BaseService, ServiceError


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
    # ---- 접근 검증 ----------------------------------------------------
    def _assert_scan_access(self, scan_id: str) -> models.Scan:
        """스캔이 호출자의 조직에 속하는지 검증한다.

        Finding 조회는 예전에 스코핑 없이 열려 있었다 (C-2). 조회 진입점마다
        이 검증을 통과하도록 해 교차 조직 열람을 막는다.
        """

        scan = self.session.get(models.Scan, scan_id)
        if scan is None:
            raise ServiceError(
                "scan not found", status_code=status.HTTP_404_NOT_FOUND
            )
        if not self.actor.is_system:
            project = self.session.get(models.Project, scan.project_id)
            if project is None:
                raise ServiceError(
                    "scan not found", status_code=status.HTTP_404_NOT_FOUND
                )
            self._assert_org(project, label="scan")
        return scan

    # ---- 조회 --------------------------------------------------------
    def for_scan(
        self, scan_id: str, *, limit: int | None = None, offset: int = 0
    ) -> list[models.Finding]:
        self._assert_scan_access(scan_id)
        return repo.list_findings_for_scan(
            self.session, scan_id, limit=limit, offset=offset
        )

    def count_for_scan(self, scan_id: str) -> int:
        self._assert_scan_access(scan_id)
        return repo.count_findings_for_scan(self.session, scan_id)

    def get(self, finding_id: int) -> models.Finding:
        row = self.session.get(models.Finding, finding_id)
        if row is None:
            raise ServiceError("finding not found", status_code=status.HTTP_404_NOT_FOUND)
        self._assert_scan_access(row.scan_id)
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
        cursor: str | None = None,
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
        # 조직 스코핑은 **항상** 적용한다. system 컨텍스트(CLI/워커)만 우회하며,
        # 그 경우에도 project_id 필터는 그대로 동작한다.
        if not self.actor.is_system:
            stmt = stmt.join(models.Scan).join(models.Project)
            filters.append(self._org_filter(models.Project))
            if project_id is not None:
                filters.append(models.Scan.project_id == project_id)
        elif project_id is not None:
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
        if cursor:
            import base64
            import json as _json

            try:
                decoded = _json.loads(base64.b64decode(cursor))
                stmt = stmt.where(
                    or_(
                        models.Finding.severity > decoded["severity"],
                        and_(
                            models.Finding.severity == decoded["severity"],
                            models.Finding.created_at < decoded["created_at"],
                        ),
                        and_(
                            models.Finding.severity == decoded["severity"],
                            models.Finding.created_at == decoded["created_at"],
                            models.Finding.id > decoded["id"],
                        ),
                    )
                )
            except (ValueError, KeyError, TypeError) as exc:
                raise ServiceError(
                    "잘못된 cursor 값입니다", status_code=status.HTTP_400_BAD_REQUEST
                ) from exc
        if filters:
            stmt = stmt.where(and_(*filters))
        stmt = (
            stmt.order_by(
                models.severity_order(),
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
