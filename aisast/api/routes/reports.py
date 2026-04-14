"""스캔 리포트 다운로드 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from aisast.api.deps import get_current_user, get_db
from aisast.db import models, repo
from aisast.reports import build_reports

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/sarif")
def download_sarif(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> Response:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    rows = repo.list_findings_for_scan(db, scan_id)
    bundle = build_reports(scan, rows)
    return Response(
        content=bundle.sarif_bytes,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f"attachment; filename={scan_id}.sarif"},
    )


@router.get("/{scan_id}/html")
def download_html(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> Response:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    rows = repo.list_findings_for_scan(db, scan_id)
    bundle = build_reports(scan, rows)
    return Response(content=bundle.html_bytes, media_type="text/html")


@router.get("/{scan_id}/excel")
def download_excel(
    scan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
) -> Response:
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    rows = repo.list_findings_for_scan(db, scan_id)
    bundle = build_reports(scan, rows)
    return Response(
        content=bundle.excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={scan_id}.xlsx"},
    )
