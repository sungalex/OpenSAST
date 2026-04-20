"""인증 라우트: 로그인 · 사용자 생성 · 계정 잠금."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db, require_role
from aisast.config import get_settings as _get_settings
from aisast.api.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from aisast.api.security import (
    PasswordPolicyError,
    clear_login_failures,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    is_refresh_consumed,
    is_user_locked,
    mark_refresh_consumed,
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
    token = create_access_token(user.email, user.role, org_id=user.organization_id)
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
    response = JSONResponse(content={
        "access_token": token,
        "role": user.role,
        "token_type": "bearer",
    })
    _settings = _get_settings()
    response.set_cookie(
        key=_settings.refresh_cookie_name,
        value=refresh,
        httponly=True,
        secure=_settings.refresh_cookie_secure,
        samesite=_settings.refresh_cookie_samesite,
        max_age=_settings.refresh_token_expire_days * 86400,
        path="/api/auth",
    )
    return response


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request: Request, db: Session = Depends(get_db)):
    _settings = _get_settings()
    # cookie 우선, 헤더 폴백
    token = request.cookies.get(_settings.refresh_cookie_name)
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="missing refresh token")
    payload = decode_access_token(token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="invalid refresh token")
    old_jti = payload.get("jti")
    if old_jti and is_refresh_consumed(old_jti):
        raise HTTPException(status_code=401, detail="refresh token already used")
    if old_jti:
        mark_refresh_consumed(old_jti)
    user = db.query(models.User).filter_by(email=payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    new_access = create_access_token(user.email, user.role, org_id=user.organization_id)
    new_refresh = create_refresh_token(user.email)
    response = JSONResponse(content={
        "access_token": new_access,
        "role": user.role,
        "token_type": "bearer",
    })
    response.set_cookie(
        key=_settings.refresh_cookie_name,
        value=new_refresh,
        httponly=True,
        secure=_settings.refresh_cookie_secure,
        samesite=_settings.refresh_cookie_samesite,
        max_age=_settings.refresh_token_expire_days * 86400,
        path="/api/auth",
    )
    return response


@router.post("/logout")
def logout(
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from aisast.api.security import blacklist_token, decode_access_token as _decode

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = _decode(token)
        if payload and "jti" in payload:
            exp = payload.get("exp", 0)
            remaining = max(int(exp - datetime.now(timezone.utc).timestamp()), 0)
            blacklist_token(payload["jti"], ttl_seconds=remaining)
    _settings = _get_settings()
    response = JSONResponse(content={"detail": "logged out"})
    response.delete_cookie(_settings.refresh_cookie_name, path="/api/auth")
    repo.record_audit(
        db,
        user_id=user.id,
        action="auth.logout",
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return response


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
