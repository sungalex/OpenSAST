"""프로젝트 CRUD 라우트 (ProjectService 위임)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from opensast.api.deps import WRITE_ROLES, get_actor, get_db, require_actor
from opensast.api.schemas import ProjectCreate, ProjectOut
from opensast.services import ActorContext, ProjectService, ServiceError

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
def list_projects_route(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> list[ProjectOut]:
    svc = ProjectService(db, actor)
    return [ProjectOut.model_validate(p) for p in svc.list_all()]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project_route(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(*WRITE_ROLES)),
) -> ProjectOut:
    svc = ProjectService(db, actor)
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
    actor: ActorContext = Depends(get_actor),
) -> ProjectOut:
    svc = ProjectService(db, actor)
    try:
        project = svc.get(project_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ProjectOut.model_validate(project)
