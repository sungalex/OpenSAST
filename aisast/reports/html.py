"""Jinja2 기반 HTML 리포트 렌더러."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aisast.db import models
from aisast.mois.catalog import MOIS_ITEMS

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def build_html(scan: models.Scan, findings: list[models.Finding]) -> bytes:
    tmpl = _env.get_template("report.html.j2")
    severity_counts = Counter(f.severity for f in findings)
    mois_coverage = Counter(f.mois_id for f in findings if f.mois_id)
    html = tmpl.render(
        scan=scan,
        findings=findings,
        severity_counts=severity_counts,
        mois_coverage=mois_coverage,
        mois_items=MOIS_ITEMS,
    )
    return html.encode("utf-8")
