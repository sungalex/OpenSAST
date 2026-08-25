"""감사 로그 조회 서비스.

감사 로그는 **조직 스코핑이 가장 중요한 테이블**이다. 로그인 시각, 조회한
Finding, 억제 규칙 변경 이력은 그 자체로 조직의 운영 정보이기 때문이다.
그런데 라우트가 `require_role("admin")` 만 걸고 ORM 을 직접 호출하고 있어,
조직 A 의 admin 이 조직 B 의 감사 로그를 전부 읽을 수 있었다
(ADR-0005 가 제거하려던 실패 모드가 이 파일 하나에 남아 있었다).

**과거 레코드 주의** — 이 서비스가 도입되기 전에 기록된 행은
`organization_id` 가 `NULL` 이다 (`repo.record_audit` 이 값을 채우지 않았다).
단일 테넌시 배포에서는 사용자도 조직 미지정이므로 그대로 보이지만, 다중
테넌시 배포에서 조직에 속한 admin 에게는 보이지 않는다. 귀속을 알 수 없는
레코드를 임의 조직에 보여주는 것보다 안전한 쪽을 택했다. 전수 조회가 필요하면
`ActorContext.system()` 컨텍스트(CLI)로만 가능하다.
"""

from __future__ import annotations

from sqlalchemy import select

from opensast.db import models
from opensast.services.base import BaseService

#: 한 번에 반환할 수 있는 최대 건수 — 라우트의 Query 상한과 일치시킨다.
MAX_LIMIT = 1000


class AuditService(BaseService):
    def list(
        self,
        *,
        action: str | None = None,
        user_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[models.AuditLog]:
        self.actor.require_role("admin")

        limit = max(1, min(limit, MAX_LIMIT))
        offset = max(0, offset)

        stmt = (
            select(models.AuditLog)
            .where(self._org_filter(models.AuditLog))
            .order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.desc())
        )
        if action:
            stmt = stmt.where(models.AuditLog.action == action)
        if user_id is not None:
            stmt = stmt.where(models.AuditLog.user_id == user_id)

        return list(self.session.scalars(stmt.offset(offset).limit(limit)))
