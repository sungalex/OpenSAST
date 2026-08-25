"""감사 로그 조회 API (admin 전용).

라우트는 얇은 어댑터다. 조회 로직과 조직 스코핑은 `AuditService` 가 가진다.
예전에는 이 파일이 `select(models.AuditLog)` 를 직접 호출해, 조직 A 의 admin 이
조직 B 의 감사 로그를 읽을 수 있었다 (ADR-0005 위반).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from opensast.api.deps import ROLE_ADMIN, get_db, require_actor
from opensast.api.schemas import AuditLogOut
from opensast.services.audit_service import AuditService
from opensast.services.base import ActorContext, ServiceError
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/admin/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    action: str | None = Query(None),
    user_id: int | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(ROLE_ADMIN)),
) -> list[AuditLogOut]:
    try:
        rows = AuditService(db, actor).list(
            action=action, user_id=user_id, limit=limit, offset=offset
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return [AuditLogOut.model_validate(r) for r in rows]
