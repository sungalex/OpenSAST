"""FastAPI 종속성 주입 유틸.

인가는 라우트 계약에서 강제된다 (ADR-0005). 서비스에 넘길 `ActorContext` 는
`get_actor` / `require_actor(...)` 의존성으로만 만들며, 라우트가 이를 빠뜨리면
서비스 생성자가 `TypeError` 를 던져 즉시 드러난다.
"""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from opensast.api.security import decode_access_token, is_blacklisted
from opensast.db import models
from opensast.db.session import get_session
from opensast.services.base import ActorContext

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# 역할 상수 — ARCHITECTURE §4.3 RBAC 표와 1:1 대응
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

#: 스캔 실행 · 프로젝트 생성 등 쓰기 작업이 허용되는 역할
WRITE_ROLES = (ROLE_ADMIN, ROLE_ANALYST)
#: 조회만 가능한 역할까지 포함한 전체
READ_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)


def get_db() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing token")
    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    jti = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token revoked")
    user = db.query(models.User).filter_by(email=payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive user")
    return user


def get_actor(
    request: Request,
    user: models.User = Depends(get_current_user),
) -> ActorContext:
    """인증된 호출자의 `ActorContext` 를 조립한다.

    조직 스코핑의 근거가 되는 `organization_id` 는 **DB 의 사용자 레코드**에서
    읽는다. JWT 클레임을 쓰지 않는 이유는, 조직 이동 후에도 기존 토큰이
    옛 조직 권한을 유지하는 것을 막기 위해서다.
    """

    return ActorContext(
        user=user,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        organization_id=getattr(user, "organization_id", None),
    )


def require_actor(*roles: str):
    """역할을 강제하면서 `ActorContext` 를 반환하는 의존성 팩토리.

    `roles` 가 비어 있으면 인증만 요구한다. 라우트는 항상 이 의존성(또는
    `get_actor`)의 결과를 서비스에 그대로 넘겨야 한다.
    """

    def dep(actor: ActorContext = Depends(get_actor)) -> ActorContext:
        if roles and actor.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role in {roles}",
            )
        return actor

    return dep


def require_role(*roles: str):
    """역할 검증 후 `User` 를 반환하는 의존성 (라우터 레벨 gate 용)."""

    def dep(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires role in {roles}",
            )
        return user

    return dep


def require_org_access(*roles: str):
    """`require_actor` 의 하위 호환 별칭."""

    return require_actor(*roles)
