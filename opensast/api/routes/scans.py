"""스캔 라우트 — 얇은 HTTP 어댑터 (ScanService 위임).

모든 라우트가 `ActorContext` 를 서비스에 주입한다 (ADR-001). 스캔 실행 계열은
`require_actor(*WRITE_ROLES)` 로 `viewer` 를 차단하며, 이는 ARCHITECTURE §4.3
RBAC 표를 코드에서 강제하는 지점이다.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session
from starlette.responses import StreamingResponse

from opensast.api.deps import (
    WRITE_ROLES,
    get_actor,
    get_db,
    require_actor,
)
from opensast.api.schemas import (
    GitScanCreate,
    ScanCreate,
    ScanDiffOut,
    ScanOut,
)
from opensast.api.security import decode_access_token, is_blacklisted
from opensast.db import models
from opensast.services import ActorContext, ScanService, ServiceError

router = APIRouter(prefix="/api/scans", tags=["scans"])

#: SSE 폴링 간격(초)
_SSE_POLL_SECONDS = 2.0
#: SSE 스트림 최대 수명(초) — 좀비 연결이 커넥션을 영구 점유하지 못하게 한다.
_SSE_MAX_SECONDS = 30 * 60


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def queue_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(*WRITE_ROLES)),
) -> ScanOut:
    try:
        scan = ScanService(db, actor).queue_from_path(
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
    project_id: int = Form(...),
    language_hint: str | None = Form(None),
    enable_second_pass: bool = Form(True),
    enable_triage: bool = Form(True),
    archive: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(*WRITE_ROLES)),
) -> ScanOut:
    try:
        scan = ScanService(db, actor).queue_from_upload(
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
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(require_actor(*WRITE_ROLES)),
) -> ScanOut:
    try:
        scan = ScanService(db, actor).queue_from_git(
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
    actor: ActorContext = Depends(get_actor),
) -> ScanOut:
    try:
        scan = ScanService(db, actor).get(scan_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return ScanOut.model_validate(scan)


@router.get("/project/{project_id}", response_model=list[ScanOut])
def list_project_scans(
    project_id: int,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> list[ScanOut]:
    try:
        rows = ScanService(db, actor).list_for_project(project_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return [ScanOut.model_validate(s) for s in rows]


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
def diff_against_previous(
    scan_id: str,
    base: str | None = None,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> ScanDiffOut:
    from opensast.api.routes.findings import _finding_to_out

    try:
        diff = ScanService(db, actor).diff(scan_id, base=base)
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
    max_bytes: int = Query(512 * 1024, ge=1, le=8 * 1024 * 1024),
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> dict:
    try:
        return ScanService(db, actor).read_source(
            scan_id, path=path, max_bytes=max_bytes
        )
    except ServiceError as exc:
        raise exc.as_http() from exc


# ---------------------------------------------------------------------------
# SSE — 진행 상태 스트리밍
# ---------------------------------------------------------------------------


def _actor_for_sse(request: Request, db: Session, token: str | None) -> ActorContext:
    """SSE 전용 인증.

    브라우저 `EventSource` 는 커스텀 헤더를 보낼 수 없으므로, Authorization
    헤더가 없을 때만 `?access_token=` 쿼리 파라미터를 대안으로 허용한다.
    검증 로직 자체는 일반 경로와 동일하다.
    """

    raw = token
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        raw = header[7:].strip()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing token"
        )
    payload = decode_access_token(raw)
    if payload is None or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        )
    jti = payload.get("jti")
    if jti and is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="token revoked"
        )
    user = db.query(models.User).filter_by(email=payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive user"
        )
    return ActorContext(
        user=user,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        organization_id=getattr(user, "organization_id", None),
    )


@router.get("/{scan_id}/events", tags=["scans"])
async def scan_events(
    scan_id: str,
    request: Request,
    access_token: str | None = Query(
        None, description="EventSource 전용 — Authorization 헤더를 쓸 수 없을 때만"
    ),
    db: Session = Depends(get_db),
):
    """Server-Sent Events 로 스캔 진행 상태를 스트리밍한다.

    인증 및 조직 스코핑을 일반 라우트와 동일하게 적용하며, 스트림이 요청 범위
    DB 세션을 붙잡고 있지 않도록 폴링마다 짧은 세션을 열고 닫는다.
    """

    actor = _actor_for_sse(request, db, access_token)
    # 구독 시작 시점에 접근 권한을 확정한다 (없는/타 조직 스캔이면 여기서 404).
    try:
        ScanService(db, actor).get(scan_id)
    except ServiceError as exc:
        raise exc.as_http() from exc

    # 지연 import — 테스트가 세션 팩토리를 교체할 수 있도록 호출 시점에 해석한다.
    from opensast.db.session import session_scope

    async def event_stream():
        elapsed = 0.0
        while elapsed < _SSE_MAX_SECONDS:
            if await request.is_disconnected():
                return
            try:
                with session_scope() as poll_session:
                    snapshot = ScanService(poll_session, actor).status_snapshot(
                        scan_id
                    )
            except ServiceError as exc:
                yield f"data: {json.dumps({'error': exc.message})}\n\n"
                return
            yield f"data: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
            if snapshot["status"] in ("completed", "failed"):
                return
            await asyncio.sleep(_SSE_POLL_SECONDS)
            elapsed += _SSE_POLL_SECONDS
        yield f"data: {json.dumps({'scan_id': scan_id, 'status': 'stream_timeout'})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
