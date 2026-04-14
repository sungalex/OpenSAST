"""인증 라우트: 로그인 · 사용자 생성."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_db, require_role
from aisast.api.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from aisast.api.security import create_access_token, hash_password, verify_password
from aisast.db import models, repo

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.query(models.User).filter_by(email=payload.email).first()
    if user is None or not verify_password(payload.password, user.hashed_password):
        repo.record_audit(
            db,
            user_id=None,
            action="auth.login_failed",
            target_type="user",
            target_id=payload.email,
            ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="inactive user")
    token = create_access_token(user.email, user.role)
    repo.record_audit(
        db,
        user_id=user.id,
        action="auth.login",
        target_type="user",
        target_id=str(user.id),
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return TokenResponse(access_token=token, role=user.role)


@router.post("/users", response_model=UserOut, dependencies=[Depends(require_role("admin"))])
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    if db.query(models.User).filter_by(email=payload.email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="user exists")
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
