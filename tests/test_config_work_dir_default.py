"""work_dir 기본값이 OS 중립적인지 검증."""

from __future__ import annotations

import tempfile
from pathlib import Path

from opensast.config import DEFAULT_WORK_DIR, Settings


def test_default_work_dir_uses_system_tempdir() -> None:
    """기본값이 `tempfile.gettempdir()` 하위여야 함."""

    expected_prefix = Path(tempfile.gettempdir()).resolve()
    actual = DEFAULT_WORK_DIR.resolve()
    assert str(actual).startswith(str(expected_prefix)) or actual == expected_prefix / "aisast-work"
    assert actual.name == "aisast-work"


def test_settings_work_dir_matches_default() -> None:
    s = Settings()
    assert s.work_dir == DEFAULT_WORK_DIR


def test_env_override_beats_default(monkeypatch) -> None:
    monkeypatch.setenv("OPENSAST_WORK_DIR", "/custom/work/dir")
    s = Settings()
    assert str(s.work_dir) == "/custom/work/dir"


def test_work_dir_is_not_hardcoded_to_var() -> None:
    """기본값이 POSIX 전용 `/var/...` 같은 하드코드가 아니어야 함."""

    default_str = str(DEFAULT_WORK_DIR)
    # /var/aisast-work 같은 하드코드 금지
    assert default_str != "/var/aisast-work"
    # Docker 경로도 아니어야 함
    assert "/var/aisast-work" not in default_str
