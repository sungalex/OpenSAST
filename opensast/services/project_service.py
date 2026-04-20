"""Project 관련 비즈니스 로직."""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from opensast.db import models, repo
from opensast.services.base import BaseService, ServiceError


class ProjectService(BaseService):
    def create(
        self,
        *,
        name: str,
        description: str = "",
        repo_url: str = "",
        default_language: str | None = None,
    ) -> models.Project:
        name = name.strip()
        if not name:
            raise ServiceError("project name is required")
        if repo.get_project_by_name(self.session, name) is not None:
            raise ServiceError(
                "project name already used", status_code=status.HTTP_409_CONFLICT
            )
        org_id = self.actor.organization_id if self.actor else None
        project = repo.create_project(
            self.session,
            name=name,
            description=description,
            repo_url=repo_url,
            default_language=default_language,
            owner_id=self.actor.user_id,
            organization_id=org_id,
        )
        self._audit(
            "project.create",
            target_type="project",
            target_id=project.id,
            detail={"name": name},
        )
        self.session.commit()
        self.session.refresh(project)
        return project

    def list_all(self) -> list[models.Project]:
        stmt = select(models.Project).where(self._org_filter(models.Project))
        return list(self.session.scalars(stmt.order_by(models.Project.id.desc())))

    def get(self, project_id: int) -> models.Project:
        project = self.session.get(models.Project, project_id)
        if project is None:
            raise ServiceError("project not found", status_code=status.HTTP_404_NOT_FOUND)
        org_id = self.actor.organization_id if self.actor else None
        if org_id is not None and project.organization_id != org_id:
            raise ServiceError("project not found", status_code=status.HTTP_404_NOT_FOUND)
        return project
