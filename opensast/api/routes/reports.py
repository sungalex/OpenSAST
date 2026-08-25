"""스캔 리포트 다운로드 라우트.

리포트도 스캔 조회와 동일한 접근 검증을 거친다 — 예전에는 ORM 을 직접 호출해
조직 스코핑을 우회했다 (C-2).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from opensast.api.deps import get_actor, get_db
from opensast.reports import build_reports
from opensast.services import ActorContext, FindingService, ScanService, ServiceError

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _bundle(db: Session, actor: ActorContext, scan_id: str):
    try:
        scan = ScanService(db, actor).get(scan_id)
        rows = FindingService(db, actor).for_scan(scan_id)
    except ServiceError as exc:
        raise exc.as_http() from exc
    return build_reports(scan, rows)


@router.get("/{scan_id}/sarif")
def download_sarif(
    scan_id: str,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> Response:
    bundle = _bundle(db, actor, scan_id)
    return Response(
        content=bundle.sarif_bytes,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f"attachment; filename={scan_id}.sarif"},
    )


@router.get("/{scan_id}/html")
def download_html(
    scan_id: str,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> Response:
    bundle = _bundle(db, actor, scan_id)
    return Response(content=bundle.html_bytes, media_type="text/html")


@router.get("/{scan_id}/excel")
def download_excel(
    scan_id: str,
    db: Session = Depends(get_db),
    actor: ActorContext = Depends(get_actor),
) -> Response:
    bundle = _bundle(db, actor, scan_id)
    return Response(
        content=bundle.excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={scan_id}.xlsx"},
    )
