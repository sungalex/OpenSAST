"""인증·인가 핵심 헬퍼 — JWT · 비밀번호 해싱 · 정책 검증 · 계정 잠금.

passlib 는 bcrypt>=4.1 과 호환 문제가 있어 사용하지 않는다. `bcrypt` 를 직접
호출하며 UTF-8 NFC 정규화 후 72 바이트 상한을 적용한다.
"""

from __future__ import annotations

import unicodedata
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from aisast.config import Settings, get_settings

_ALGORITHM = "HS256"
_BCRYPT_MAX_BYTES = 72


def _prepare(plain: str) -> bytes:
    return unicodedata.normalize("NFC", plain).encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_prepare(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    subject: str, role: str, org_id: int | None = None
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": subject,
        "role": role,
        "exp": expires,
        "iat": now,
        "jti": uuid.uuid4().hex,
        "type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "org_id": org_id,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)
    payload = {
        "sub": subject,
        "exp": expires,
        "iat": now,
        "jti": uuid.uuid4().hex,
        "type": "refresh",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[_ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# 비밀번호 정책
# ---------------------------------------------------------------------------

_COMMON_PASSWORDS = {
    "password",
    "passw0rd",
    "12345678",
    "qwerty123",
    "admin123",
    "letmein12",
    "welcome1234",
    "aisast-admin",
    "qwerty1234",
    "iloveyou123",
    "monkey1234",
    "dragon1234",
    "master123",
}


class PasswordPolicyError(ValueError):
    """비밀번호 정책 위반."""


def validate_password_policy(
    password: str, *, settings: Settings | None = None
) -> None:
    """정책 위반 시 `PasswordPolicyError` 를 raise."""

    settings = settings or get_settings()
    if len(password) < settings.password_min_length:
        raise PasswordPolicyError(
            f"password must be at least {settings.password_min_length} characters"
        )
    classes = sum(
        bool(fn(password))
        for fn in (
            lambda s: any(c.islower() for c in s),
            lambda s: any(c.isupper() for c in s),
            lambda s: any(c.isdigit() for c in s),
            lambda s: any(not c.isalnum() for c in s),
        )
    )
    if classes < settings.password_required_classes:
        raise PasswordPolicyError(
            f"password must include at least {settings.password_required_classes} "
            "of: lowercase, uppercase, digit, special"
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("password is in the common-passwords blacklist")
    for i in range(len(password) - 3):
        if password[i] == password[i + 1] == password[i + 2] == password[i + 3]:
            raise PasswordPolicyError("password contains 4+ repeated characters")


# ---------------------------------------------------------------------------
# 계정 잠금
# ---------------------------------------------------------------------------


def is_user_locked(user, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    locked_until = getattr(user, "locked_until", None)
    if locked_until is None:
        return False
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now


def register_failed_login(user, *, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    user.failed_attempts = (getattr(user, "failed_attempts", 0) or 0) + 1
    if user.failed_attempts >= settings.failed_login_threshold:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.failed_login_lockout_minutes
        )
        return True
    return False


def clear_login_failures(user) -> None:
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 토큰 블랙리스트 (Redis)
# ---------------------------------------------------------------------------


def blacklist_token(jti: str, ttl_seconds: int | None = None) -> None:
    """JWT jti를 블랙리스트에 추가."""
    try:
        import redis

        settings = get_settings()
        r = redis.from_url(settings.redis_url)
        ttl = ttl_seconds or (settings.access_token_expire_minutes * 60)
        r.setex(f"blacklist:{jti}", max(ttl, 1), "1")
    except Exception:
        pass  # Redis 장애 시 fail-open


def is_blacklisted(jti: str) -> bool:
    """jti가 블랙리스트에 있는지 확인."""
    try:
        import redis

        r = redis.from_url(get_settings().redis_url)
        return r.exists(f"blacklist:{jti}") > 0
    except Exception:
        return False  # Redis 장애 시 fail-open


# ---------------------------------------------------------------------------
# Refresh token rotation
# ---------------------------------------------------------------------------


def mark_refresh_consumed(jti: str, ttl_seconds: int = 7 * 86400) -> None:
    """사용된 refresh token jti를 기록."""
    try:
        import redis

        r = redis.from_url(get_settings().redis_url)
        r.setex(f"refresh_consumed:{jti}", ttl_seconds, "1")
    except Exception:
        pass


def is_refresh_consumed(jti: str) -> bool:
    """이미 사용된 refresh token인지 확인."""
    try:
        import redis

        r = redis.from_url(get_settings().redis_url)
        return r.exists(f"refresh_consumed:{jti}") > 0
    except Exception:
        return False
