"""조직(테넌트) 레지스트리 서비스.

`organizations` 는 다른 테이블과 성격이 다르다. `organization_id` 컬럼을 가진
쪽이 아니라 **스코핑의 기준이 되는 쪽**이므로 `_org_filter()` 를 그대로 쓸 수
없다. 대신 다음 규칙을 명시적으로 적용한다.

| 호출자 | 목록 | 상세 | 생성 |
|---|---|---|---|
| `ActorContext.system()` | 전체 | 전체 | 가능 |
| admin, 조직 미지정(플랫폼 관리자) | 전체 | 전체 | 가능 |
| 조직 소속 사용자 (역할 무관) | 자기 조직 1건 | 자기 조직만 | 불가 |

조직 미지정 admin 을 플랫폼 관리자로 보는 것은 이 코드베이스의 단일 테넌시
배포 형태를 그대로 따른 것이다 (사용자 `organization_id` 가 `NULL`). 조직에
속한 admin 은 자기 테넌트의 관리자일 뿐이므로 다른 조직을 열거하거나 새 조직을
만들 수 없다.

이전 구현은 `get_current_user` 만 요구하고 전체 조직을 반환해, `viewer` 권한
사용자도 모든 테넌트의 slug·name 을 열거할 수 있었다.
"""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from opensast.db import models
from opensast.services.base import BaseService, ServiceError


class OrganizationService(BaseService):
    # ---- 권한 판정 -------------------------------------------------------
    @property
    def _is_platform_admin(self) -> bool:
        """전체 조직을 다룰 수 있는 호출자인가."""

        if self.actor.is_system:
            return True
        return self.actor.role == "admin" and self.actor.organization_id is None

    # ---- 조회 -----------------------------------------------------------
    def list(self) -> list[models.Organization]:
        stmt = select(models.Organization).order_by(models.Organization.id)
        if not self._is_platform_admin:
            if self.actor.organization_id is None:
                return []
            stmt = stmt.where(models.Organization.id == self.actor.organization_id)
        return list(self.session.scalars(stmt))

    def get(self, org_id: int) -> models.Organization:
        org = self.session.get(models.Organization, org_id)
        if org is None:
            raise ServiceError(
                "organization not found", status_code=status.HTTP_404_NOT_FOUND
            )
        if not self._is_platform_admin and org.id != self.actor.organization_id:
            # 존재 여부를 노출하지 않기 위해 403 이 아니라 404 로 막는다.
            raise ServiceError(
                "organization not found", status_code=status.HTTP_404_NOT_FOUND
            )
        return org

    # ---- 생성 -----------------------------------------------------------
    def create(self, *, slug: str, name: str) -> models.Organization:
        if not self._is_platform_admin:
            raise ServiceError(
                "creating an organization requires a platform administrator",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        slug = (slug or "").strip()
        name = (name or "").strip()
        if not slug or not name:
            raise ServiceError("slug and name are required")

        if self.session.scalar(
            select(models.Organization).where(models.Organization.slug == slug)
        ):
            raise ServiceError(
                "slug already exists", status_code=status.HTTP_409_CONFLICT
            )

        org = models.Organization(slug=slug, name=name, is_active=True)
        self.session.add(org)
        self.session.flush()
        self._audit("organization.create", target_type="organization", target_id=org.id)
        self.session.commit()
        self.session.refresh(org)
        return org
