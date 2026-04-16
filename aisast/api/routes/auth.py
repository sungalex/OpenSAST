"""인증 라우트: 로그인 · 사용자 생성 · 계정 잠금."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_db, require_role
from aisast.api.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from aisast.api.security import (
    PasswordPolicyError,
    clear_login_failures,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    is_user_locked,
    register_failed_login,
    validate_password_policy,
    verify_password,
)
from aisast.db import models, repo

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.query(models.User).filter_by(email=payload.email).first()
    ip = request.client.host if request.client else None

    if user is None:
        repo.record_audit(
            db,
            user_id=None,
            action="auth.login_failed",
            target_type="user",
            target_id=payload.email,
            detail={"reason": "unknown_user"},
            ip=ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    if is_user_locked(user):
        repo.record_audit(
            db,
            user_id=user.id,
            action="auth.login_locked",
            target_type="user",
            target_id=str(user.id),
            detail={"locked_until": str(user.locked_until)},
            ip=ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="계정이 잠겨 있습니다. 잠시 후 다시 시도하세요.",
        )

    if not verify_password(payload.password, user.hashed_password):
        newly_locked = register_failed_login(user)
        repo.record_audit(
            db,
            user_id=user.id,
            action="auth.login_failed",
            target_type="user",
            target_id=str(user.id),
            detail={
                "attempts": user.failed_attempts,
                "locked": newly_locked,
            },
            ip=ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="inactive user"
        )

    clear_login_failures(user)
    token = create_access_token(user.email, user.role)
    refresh = create_refresh_token(user.email)
    repo.record_audit(
        db,
        user_id=user.id,
        action="auth.login",
        target_type="user",
        target_id=str(user.id),
        ip=ip,
    )
    db.commit()
    return TokenResponse(access_token=token, refresh_token=refresh, role=user.role)


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing refresh token")
    token = auth_header[7:]
    payload = decode_access_token(token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="invalid refresh token")
    user = db.query(models.User).filter_by(email=payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    new_access = create_access_token(user.email, user.role)
    new_refresh = create_refresh_token(user.email)
    return TokenResponse(access_token=new_access, refresh_token=new_refresh, role=user.role)


@router.post(
    "/users",
    response_model=UserOut,
    dependencies=[Depends(require_role("admin"))],
)
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    if db.query(models.User).filter_by(email=payload.email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="user exists")
    try:
        validate_password_policy(payload.password)
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    user = models.User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        display_name=payload.display_name,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)
