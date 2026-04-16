"""스캔 라우트 — 얇은 HTTP 어댑터 (ScanService 위임)."""

from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.api.schemas import (
    GitScanCreate,
    ScanCreate,
    ScanDiffOut,
    ScanOut,
)
from aisast.db import models
from aisast.services import ActorContext, ScanService, ServiceError

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _actor(request: Request, user: models.User) -> ActorContext:
    return ActorContext(
        user=user,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def queue_scan(
    payload: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanOut:
    svc = ScanService(db, _actor(request, user))
    try:
        scan = svc.queue_from_path(
            project_id=payload.project_id,
            source_path=payload.source_path,
            language_hint=payload.language_hint,
            enable_second_pass=payload.enable_second_pass,
            enable_triage=payload.enable_triage,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanOut.model_validate(scan)


@router.post("/upload", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def upload_and_scan(
    request: Request,
    project_id: int = Form(...),
    language_hint: str | None = Form(None),
    enable_second_pass: bool = Form(True),
    enable_triage: bool = Form(True),
    archive: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanOut:
    svc = ScanService(db, _actor(request, user))
    try:
        scan = svc.queue_from_upload(
            project_id=project_id,
            archive=archive,
            language_hint=language_hint,
            enable_second_pass=enable_second_pass,
            enable_triage=enable_triage,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanOut.model_validate(scan)


@router.post("/git", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def clone_and_scan(
    payload: GitScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanOut:
    svc = ScanService(db, _actor(request, user))
    try:
        scan = svc.queue_from_git(
            project_id=payload.project_id,
            git_url=payload.git_url,
            branch=payload.branch,
            language_hint=payload.language_hint,
            enable_second_pass=payload.enable_second_pass,
            enable_triage=payload.enable_triage,
        )
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanOut:
    try:
        scan = ScanService(db).get(scan_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanOut.model_validate(scan)


@router.get("/project/{project_id}", response_model=list[ScanOut])
def list_project_scans(
    project_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ScanOut]:
    svc = ScanService(db)
    return [ScanOut.model_validate(s) for s in svc.list_for_project(project_id)]


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
def diff_against_previous(
    scan_id: str,
    base: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanDiffOut:
    from aisast.api.routes.findings import _finding_to_out

    try:
        diff = ScanService(db).diff(scan_id, base=base)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanDiffOut(
        base_scan_id=diff["base_scan_id"],
        head_scan_id=diff["head_scan_id"],
        new=[_finding_to_out(f) for f in diff["new"]],
        resolved=[_finding_to_out(f) for f in diff["resolved"]],
        persistent=diff["persistent"],
        summary=diff["summary"],
    )


@router.get("/{scan_id}/source")
def read_source_file(
    scan_id: str,
    path: str,
    max_bytes: int = 512 * 1024,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    try:
        return ScanService(db).read_source(scan_id, path=path, max_bytes=max_bytes)
    except ServiceError as exc:
        raise exc.as_http() from exc


@router.get("/{scan_id}/events", tags=["scans"])
async def scan_events(scan_id: str, db: Session = Depends(get_db)):
    """Server-Sent Events 로 스캔 진행 상태를 스트리밍한다."""
    import asyncio

    from starlette.responses import StreamingResponse

    async def event_stream():
        while True:
            scan = db.get(models.Scan, scan_id)
            if scan is None:
                yield f'data: {{"error": "scan not found"}}\n\n'
                return
            status = scan.status
            yield f'data: {{"scan_id": "{scan_id}", "status": "{status}"}}\n\n'
            if status in ("completed", "failed"):
                return
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")
