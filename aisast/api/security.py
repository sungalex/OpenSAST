"""JWT 발급·검증 및 비밀번호 해싱.

passlib는 2025년 기준 유지보수가 중단되었고 최신 bcrypt(>=4.1)와 호환성 문제가
있어, 본 모듈은 `bcrypt` 라이브러리를 직접 사용한다. bcrypt는 72바이트까지만
처리하므로 UTF-8 인코딩 후 상한을 적용한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from aisast.config import get_settings

_ALGORITHM = "HS256"
_BCRYPT_MAX_BYTES = 72


def _prepare(plain: str) -> bytes:
    return plain.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_prepare(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(subject: str, role: str) -> str:
    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {"sub": subject, "role": role, "exp": expires}
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])
    except JWTError:
        return None
