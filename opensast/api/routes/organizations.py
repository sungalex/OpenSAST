"""조직(테넌트) 레지스트리 API.

스코핑 규칙은 `OrganizationService` 의 docstring 에 있다. 요약하면 조직에 속한
사용자는 자기 조직만 보고, 조직 미지정 admin(= 플랫폼 관리자)과 시스템
컨텍스트만 전체를 다룬다.

예전에는 목록·상세가 `get_current_user` 만 요구하고 전체 조직을 반환해,
`viewer` 권한 사용자도 모든 테넌트의 slug·name 을 열거할 수 있었다.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from opensast.api.deps import ROLE_ADMIN, get_actor, get_db, require_actor
from opensast.api.schemas import OrganizationCreate, OrganizationOut
from opensast.services.base import ActorContext, ServiceError
from opensast.services.organization_service import OrganizationService

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


@router.post("", status_code=201, response_model=OrganizationOut)
def create_org(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> OrganizationOut:
    try:
        org = OrganizationService(db, actor).create(
            slug=payload.slug, name=payload.name
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return OrganizationOut.model_validate(org)


@router.get("", response_model=list[OrganizationOut])
def list_orgs(
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> list[OrganizationOut]:
    orgs = OrganizationService(db, actor).list()
    return [OrganizationOut.model_validate(o) for o in orgs]


@router.get("/{org_id}", response_model=OrganizationOut)
def get_org(
    org_id: int,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> OrganizationOut:
    try:
        org = OrganizationService(db, actor).get(org_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return OrganizationOut.model_validate(org)
