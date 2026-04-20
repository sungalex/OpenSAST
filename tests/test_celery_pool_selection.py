"""Celery pool 플랫폼 감지 로직 검증."""

from __future__ import annotations

import sys

import pytest

from opensast.orchestrator.celery_app import recommended_pool


def test_default_pool_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENSAST_CELERY_POOL", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    assert recommended_pool() == "prefork"


def test_default_pool_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENSAST_CELERY_POOL", raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert recommended_pool() == "prefork"


def test_default_pool_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENSAST_CELERY_POOL", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    assert recommended_pool() == "solo"


def test_env_override_forces_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSAST_CELERY_POOL", "gevent")
    monkeypatch.setattr(sys, "platform", "linux")
    assert recommended_pool() == "gevent"


def test_env_override_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSAST_CELERY_POOL", "  SOLO  ")
    monkeypatch.setattr(sys, "platform", "linux")
    assert recommended_pool() == "solo"
