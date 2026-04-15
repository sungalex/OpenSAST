"""비밀번호 정책 + 계정 잠금 로직 검증."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from aisast.api.security import (
    PasswordPolicyError,
    clear_login_failures,
    is_user_locked,
    register_failed_login,
    validate_password_policy,
)
from aisast.config import Settings


def _loose_settings() -> Settings:
    return Settings(
        password_min_length=12,
        password_required_classes=3,
        failed_login_threshold=3,
        failed_login_lockout_minutes=10,
    )


def test_password_too_short() -> None:
    with pytest.raises(PasswordPolicyError, match="at least"):
        validate_password_policy("Short1!", settings=_loose_settings())


def test_password_missing_classes() -> None:
    # 12자 이상이지만 소문자+숫자 2종 뿐
    with pytest.raises(PasswordPolicyError, match="include at least"):
        validate_password_policy("onlyletters1", settings=_loose_settings())


def test_password_common_blacklist() -> None:
    # 길이·class 체크를 건너뛸 수 있도록 느슨한 settings 사용
    loose = Settings(password_min_length=1, password_required_classes=1)
    with pytest.raises(PasswordPolicyError, match="common"):
        validate_password_policy("password", settings=loose)


def test_password_repeated_chars() -> None:
    # 소문자 'a' 연속 4개 + upper/digit/special 로 class 3종 충족
    with pytest.raises(PasswordPolicyError, match="repeated"):
        validate_password_policy("aaaa!B34567890", settings=_loose_settings())


def test_password_accepts_valid() -> None:
    validate_password_policy("Strong#Pass1", settings=_loose_settings())


def test_is_user_locked_before_expiry() -> None:
    user = SimpleNamespace(
        failed_attempts=5,
        locked_until=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    assert is_user_locked(user) is True


def test_is_user_locked_after_expiry() -> None:
    user = SimpleNamespace(
        failed_attempts=5,
        locked_until=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    assert is_user_locked(user) is False


def test_register_failed_login_triggers_lock() -> None:
    settings = _loose_settings()
    user = SimpleNamespace(failed_attempts=0, locked_until=None)

    assert register_failed_login(user, settings=settings) is False
    assert user.failed_attempts == 1
    assert user.locked_until is None

    assert register_failed_login(user, settings=settings) is False
    assert register_failed_login(user, settings=settings) is True
    assert user.failed_attempts == 3
    assert user.locked_until is not None


def test_clear_login_failures() -> None:
    user = SimpleNamespace(
        failed_attempts=3,
        locked_until=datetime.now(timezone.utc),
        last_login_at=None,
    )
    clear_login_failures(user)
    assert user.failed_attempts == 0
    assert user.locked_until is None
    assert user.last_login_at is not None
