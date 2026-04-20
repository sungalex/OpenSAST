"""통합 리포트 생성 패키지."""

from dataclasses import dataclass

from opensast.db import models
from opensast.reports.excel import build_excel
from opensast.reports.html import build_html
from opensast.reports.pdf import build_pdf
from opensast.reports.sarif import build_sarif


@dataclass
class ReportBundle:
    sarif_bytes: bytes
    html_bytes: bytes
    excel_bytes: bytes
    pdf_bytes: bytes


def build_reports(scan: models.Scan, findings: list[models.Finding]) -> ReportBundle:
    sarif = build_sarif(scan, findings)
    html = build_html(scan, findings)
    excel = build_excel(scan, findings)
    pdf = build_pdf(html)
    return ReportBundle(
        sarif_bytes=sarif,
        html_bytes=html,
        excel_bytes=excel,
        pdf_bytes=pdf,
    )


__all__ = ["ReportBundle", "build_reports", "build_sarif", "build_html", "build_excel", "build_pdf"]
