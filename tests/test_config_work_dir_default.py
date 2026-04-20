"""work_dir 기본값이 프로젝트-상대 `.opensast-work` 폴더를 가리키는지 검증."""

from __future__ import annotations

from pathlib import Path

from opensast.config import DEFAULT_WORK_DIR, Settings


def test_default_work_dir_is_project_relative() -> None:
    """기본값이 숨김 `.opensast-work` 폴더이고 OS 임시 디렉터리가 아니어야 함."""

    assert DEFAULT_WORK_DIR.name == ".opensast-work"
    assert "/tmp/" not in str(DEFAULT_WORK_DIR)
    assert "/var/folders/" not in str(DEFAULT_WORK_DIR)


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
    assert default_str != "/var/opensast-work"
    assert "/var/opensast-work" not in default_str


def test_default_work_dir_resolves_under_cwd() -> None:
    """기본값은 실행 시점 CWD 기준이므로 그 하위에 위치해야 함."""

    assert DEFAULT_WORK_DIR.parent == Path.cwd()
