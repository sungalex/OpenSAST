"""프로젝트 단위 탐지 제외 규칙 서비스."""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from opensast.db import models
from opensast.services.base import BaseService, ServiceError


class SuppressionService(BaseService):
    def _verify_project_access(self, project_id: int) -> models.Project:
        """프로젝트 존재 + 조직 스코핑 검증."""
        project = self.session.get(models.Project, project_id)
        if project is None:
            raise ServiceError(
                "project not found", status_code=status.HTTP_404_NOT_FOUND
            )
        org_id = self.actor.organization_id if self.actor else None
        if org_id is not None and project.organization_id != org_id:
            raise ServiceError(
                "project not found", status_code=status.HTTP_404_NOT_FOUND
            )
        return project

    def list_for_project(self, project_id: int) -> list[models.SuppressionRule]:
        self._verify_project_access(project_id)
        return list(
            self.session.scalars(
                select(models.SuppressionRule).where(
                    models.SuppressionRule.project_id == project_id
                )
            )
        )

    def create(
        self,
        *,
        project_id: int,
        kind: str,
        pattern: str,
        rule_id: str | None,
        reason: str,
    ) -> models.SuppressionRule:
        project = self._verify_project_access(project_id)
        row = models.SuppressionRule(
            project_id=project_id,
            kind=kind,
            pattern=pattern,
            rule_id=rule_id,
            reason=reason,
            created_by=self.actor.user_id,
        )
        self.session.add(row)
        self._audit(
            "suppression.create",
            target_type="project",
            target_id=project_id,
            detail={"kind": kind, "pattern": pattern, "rule_id": rule_id},
        )
        self.session.commit()
        self.session.refresh(row)
        return row

    def delete(self, *, project_id: int, suppression_id: int) -> None:
        self._verify_project_access(project_id)
        row = self.session.get(models.SuppressionRule, suppression_id)
        if row is None or row.project_id != project_id:
            raise ServiceError(
                "suppression not found", status_code=status.HTTP_404_NOT_FOUND
            )
        self.session.delete(row)
        self._audit(
            "suppression.delete",
            target_type="project",
            target_id=project_id,
            detail={"id": suppression_id},
        )
        self.session.commit()
