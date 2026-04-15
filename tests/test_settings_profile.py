"""설정 프로파일 default/검증 동작."""

from __future__ import annotations

import pytest

from aisast.config import Profile, Settings


def test_local_profile_defaults_loose() -> None:
    s = Settings(profile=Profile.LOCAL).apply_profile_defaults()
    assert s.enable_docs is True
    assert s.enforce_strong_secret is False
    assert s.rate_limit_per_minute == 0
    assert "*" in s.cors_origins


def test_docker_profile_defaults() -> None:
    s = Settings(profile=Profile.DOCKER).apply_profile_defaults()
    assert s.enable_docs is True
    assert s.rate_limit_per_minute == 100
    assert "http://localhost:5173" in s.cors_origins


def test_cloud_profile_defaults_strict() -> None:
    s = Settings(profile=Profile.CLOUD).apply_profile_defaults()
    assert s.enable_docs is False
    assert s.enforce_strong_secret is True
    assert s.enforce_https is True
    assert s.log_format == "json"
    assert s.rate_limit_per_minute == 60


def test_cloud_profile_validation_rejects_weak_secret() -> None:
    s = Settings(
        profile=Profile.CLOUD,
        secret_key="change-me",
        cors_origins=["https://sast.example.com"],
    ).apply_profile_defaults()
    warnings = s.validate_profile()
    assert any("secret_key" in w.lower() or "약함" in w for w in warnings)


def test_cloud_profile_validation_rejects_default_bootstrap() -> None:
    s = Settings(
        profile=Profile.CLOUD,
        secret_key="a" * 64,
        cors_origins=["https://sast.example.com"],
    ).apply_profile_defaults()
    warnings = s.validate_profile()
    assert any("부트스트랩" in w for w in warnings)


def test_env_override_beats_profile_default() -> None:
    """사용자가 명시한 env 값은 프로파일 기본값이 덮지 않아야 한다."""

    s = Settings(
        profile=Profile.CLOUD,
        cors_origins=["https://custom.example.com"],
    )
    # cors_origins 는 사용자 명시 → profile defaults 가 덮지 않음
    s.apply_profile_defaults()
    assert s.cors_origins == ["https://custom.example.com"]


def test_cors_origins_comma_string() -> None:
    s = Settings(cors_origins="https://a.com,https://b.com")
    assert s.cors_origins == ["https://a.com", "https://b.com"]
