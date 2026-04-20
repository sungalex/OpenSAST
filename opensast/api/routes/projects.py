"""프로젝트 CRUD 라우트 (ProjectService 위임)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from opensast.api.deps import get_current_user, get_db
from opensast.api.schemas import ProjectCreate, ProjectOut
from opensast.db import models
from opensast.services import ActorContext, ProjectService, ServiceError

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.get("", response_model=list[ProjectOut])
def list_projects_route(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ProjectOut]:
    svc = ProjectService(db)
    return [ProjectOut.model_validate(p) for p in svc.list_all()]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project_route(
    payload: ProjectCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ProjectOut:
    svc = ProjectService(db, _actor(request, user))
    try:
        project = svc.create(
            name=payload.name,
            description=payload.description,
            repo_url=payload.repo_url,
            default_language=payload.default_language,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project_route(
    project_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ProjectOut:
    svc = ProjectService(db)
    try:
        project = svc.get(project_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ProjectOut.model_validate(project)
