"""스캔 작업 큐잉·조회 라우트.

소스 코드 지정 3가지 모드:
  1. 서버 경로 — `POST /api/scans`: api/worker 컨테이너가 이미 볼 수 있는 경로
  2. ZIP 업로드 — `POST /api/scans/upload`: 브라우저에서 .zip 파일 업로드
  3. Git URL — `POST /api/scans/git`: 공개/토큰 포함 URL을 worker 가 clone 후 스캔

②와 ③은 `settings.work_dir` 아래 임시 디렉터리에 풀어지며, api·worker 가 동일한
경로를 볼 수 있도록 compose 의 `aisast-work` 볼륨을 공유한다.
"""

from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import GitScanCreate, ScanCreate, ScanOut
from aisast.config import get_settings
from aisast.db import models, repo
from aisast.orchestrator.tasks import clone_and_scan_task, run_scan_task
from aisast.utils.logging import get_logger
from aisast.utils.paths import ensure_dir

log = get_logger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

_MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MiB
_ALLOWED_UPLOAD_SUFFIXES = {".zip"}


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def queue_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> ScanOut:
    """기존 방식: 서버 파일시스템 경로를 받아 큐잉."""

    project = _get_project_or_404(db, payload.project_id)
    scan_id = uuid.uuid4().hex[:12]
    repo.create_scan_record(
        db,
        scan_id=scan_id,
        project_id=project.id,
        source_path=payload.source_path,
    )
    db.commit()
    run_scan_task.delay(
        scan_id,
        payload.source_path,
        payload.enable_second_pass,
        payload.enable_triage,
        payload.language_hint,
    )
    scan = db.get(models.Scan, scan_id)
    return ScanOut.model_validate(scan)


@router.post("/upload", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def upload_and_scan(
    project_id: int = Form(...),
    language_hint: str | None = Form(None),
    enable_second_pass: bool = Form(True),
    enable_triage: bool = Form(True),
    archive: UploadFile = File(...),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> ScanOut:
    """브라우저에서 업로드한 ZIP 아카이브를 풀고 스캔."""

    project = _get_project_or_404(db, project_id)
    _validate_archive(archive)

    settings = get_settings()
    scan_id = uuid.uuid4().hex[:12]
    work_root = Path(settings.work_dir)
    scan_root = work_root / "sources" / scan_id
    archive_path = work_root / "uploads" / f"{scan_id}.zip"
    ensure_dir(scan_root)
    ensure_dir(archive_path.parent)

    total = _stream_upload_to_disk(archive, archive_path)
    log.info("scan %s uploaded %d bytes", scan_id, total)

    try:
        _safe_extract_zip(archive_path, scan_root)
    except Exception as exc:
        shutil.rmtree(scan_root, ignore_errors=True)
        archive_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"zip 압축 해제 실패: {exc}",
        ) from exc
    finally:
        archive_path.unlink(missing_ok=True)

    source_path = str(scan_root)
    repo.create_scan_record(
        db, scan_id=scan_id, project_id=project.id, source_path=source_path
    )
    db.commit()
    run_scan_task.delay(
        scan_id, source_path, enable_second_pass, enable_triage, language_hint
    )
    scan = db.get(models.Scan, scan_id)
    return ScanOut.model_validate(scan)


@router.post("/git", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def clone_and_scan(
    payload: GitScanCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> ScanOut:
    """Git 원격 저장소를 clone 한 뒤 스캔."""

    project = _get_project_or_404(db, payload.project_id)
    scan_id = uuid.uuid4().hex[:12]
    repo.create_scan_record(
        db,
        scan_id=scan_id,
        project_id=project.id,
        source_path=f"git:{payload.git_url}@{payload.branch or 'HEAD'}",
    )
    db.commit()
    clone_and_scan_task.delay(
        scan_id,
        payload.git_url,
        payload.branch,
        payload.enable_second_pass,
        payload.enable_triage,
        payload.language_hint,
    )
    scan = db.get(models.Scan, scan_id)
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> ScanOut:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return ScanOut.model_validate(scan)


@router.get("/project/{project_id}", response_model=list[ScanOut])
def list_project_scans(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> list[ScanOut]:
    return [
        ScanOut.model_validate(s)
        for s in repo.list_scans_for_project(db, project_id)
    ]


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------


def _get_project_or_404(db: Session, project_id: int) -> models.Project:
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="project not found"
        )
    return project


def _validate_archive(archive: UploadFile) -> None:
    name = (archive.filename or "").lower()
    suffix = Path(name).suffix
    if suffix not in _ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"지원하지 않는 형식: {suffix or '없음'} — .zip 만 가능",
        )


def _stream_upload_to_disk(archive: UploadFile, dest: Path) -> int:
    total = 0
    chunk_size = 1024 * 1024
    with dest.open("wb") as f:
        while True:
            chunk = archive.file.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_UPLOAD_BYTES:
                dest.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"업로드 크기 제한 초과 ({_MAX_UPLOAD_BYTES} bytes)",
                )
            f.write(chunk)
    return total


def _safe_extract_zip(archive_path: Path, dest_dir: Path) -> None:
    """Zip-slip 방지 압축 해제."""

    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.infolist():
            member_path = (dest_dir / member.filename).resolve()
            if not str(member_path).startswith(str(dest_resolved)):
                raise ValueError(
                    f"zip 엔트리가 대상 경로를 벗어납니다: {member.filename}"
                )
        zf.extractall(dest_dir)
