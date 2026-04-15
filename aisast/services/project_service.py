"""Project 관련 비즈니스 로직."""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from aisast.db import models, repo
from aisast.services.base import BaseService, ServiceError


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
        project = repo.create_project(
            self.session,
            name=name,
            description=description,
            repo_url=repo_url,
            default_language=default_language,
            owner_id=self.actor.user_id,
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
        return repo.list_projects(self.session)

    def get(self, project_id: int) -> models.Project:
        project = self.session.get(models.Project, project_id)
        if project is None:
            raise ServiceError("project not found", status_code=status.HTTP_404_NOT_FOUND)
        return project
