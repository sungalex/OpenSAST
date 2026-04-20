"""스캔 업로드 라우트의 보조 유틸 검증."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from opensast.services.scan_service import ScanService

_safe_extract_zip = ScanService._safe_extract_zip


def _write_zip(
    tmp_path: Path, entries: dict[str, bytes], name: str = "archive.zip"
) -> Path:
    archive = tmp_path / name
    with zipfile.ZipFile(archive, "w") as zf:
        for arcname, data in entries.items():
            zf.writestr(arcname, data)
    return archive


def test_safe_extract_normal_files(tmp_path: Path) -> None:
    archive = _write_zip(
        tmp_path,
        {
            "src/app.py": b"print('hi')\n",
            "README.md": b"# sample\n",
        },
    )
    dest = tmp_path / "out"
    dest.mkdir()
    _safe_extract_zip(archive, dest)
    assert (dest / "src" / "app.py").read_bytes().startswith(b"print")
    assert (dest / "README.md").exists()


def test_safe_extract_rejects_zip_slip(tmp_path: Path) -> None:
    archive = _write_zip(
        tmp_path,
        {"../evil.txt": b"pwned"},
        name="slip.zip",
    )
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ValueError, match="대상 경로를 벗어"):
        _safe_extract_zip(archive, dest)
    assert not (tmp_path / "evil.txt").exists()


def test_git_scan_create_rejects_invalid_url() -> None:
    from opensast.api.schemas import GitScanCreate

    with pytest.raises(ValueError):
        GitScanCreate(project_id=1, git_url="file:///etc/passwd")
    ok = GitScanCreate(project_id=1, git_url="https://github.com/x/y.git")
    assert ok.git_url == "https://github.com/x/y.git"
