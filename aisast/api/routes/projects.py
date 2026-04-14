"""프로젝트 CRUD 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import ProjectCreate, ProjectOut
from aisast.db import models, repo

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
def list_projects_route(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[ProjectOut]:
    return [ProjectOut.model_validate(p) for p in repo.list_projects(db)]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project_route(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ProjectOut:
    if repo.get_project_by_name(db, payload.name) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="project name already used"
        )
    project = repo.create_project(
        db,
        name=payload.name,
        description=payload.description,
        repo_url=payload.repo_url,
        default_language=payload.default_language,
        owner_id=user.id,
    )
    db.commit()
    db.refresh(project)
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project_route(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> ProjectOut:
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return ProjectOut.model_validate(project)
