"""통합 리포트 생성 패키지.

리포트 포맷은 `opensast.reports` entry_point 그룹으로 확장할 수 있다.
예전에는 `report_registry` 가 정의만 되고 `build_reports()` 가 4개 빌더를 직접
호출해, 문서에 있는 플러그인 확장 경로가 실행 경로에는 없었다 (P6).

외부 패키지 등록 예:

```toml
[project.entry-points."opensast.reports"]
csv = "my_plugin:build_csv"
```

`build_report(name, scan, findings) -> bytes` 규약을 따르면 `build_reports()`
결과의 `extra` 에 담긴다.
"""

from dataclasses import dataclass, field

from opensast.db import models
from opensast.plugins.registry import report_registry
from opensast.reports.excel import build_excel
from opensast.reports.html import build_html
from opensast.reports.pdf import build_pdf
from opensast.reports.sarif import build_sarif
from opensast.utils.logging import get_logger

log = get_logger(__name__)

# 내장 포맷을 레지스트리에 등록 (priority=50 = 내장)
for _name, _fn in (
    ("sarif", build_sarif),
    ("html", build_html),
    ("excel", build_excel),
):
    report_registry.register(_name, _fn, source="builtin", priority=50)


@dataclass
class ReportBundle:
    sarif_bytes: bytes
    html_bytes: bytes
    excel_bytes: bytes
    pdf_bytes: bytes
    #: 플러그인이 추가한 포맷 — {이름: bytes}
    extra: dict[str, bytes] = field(default_factory=dict)


def build_report(name: str, scan: models.Scan, findings: list[models.Finding]) -> bytes:
    """레지스트리에서 포맷 하나를 찾아 생성한다."""

    return report_registry.get(name).factory(scan, findings)


def build_reports(scan: models.Scan, findings: list[models.Finding]) -> ReportBundle:
    sarif = build_sarif(scan, findings)
    html = build_html(scan, findings)
    excel = build_excel(scan, findings)
    pdf = build_pdf(html)

    extra: dict[str, bytes] = {}
    for plugin in report_registry.all():
        if plugin.source == "builtin":
            continue
        try:
            extra[plugin.name] = plugin.factory(scan, findings)
        except Exception as exc:  # noqa: BLE001 - 플러그인 실패는 격리
            log.warning("report plugin %r failed: %s", plugin.name, exc)

    return ReportBundle(
        sarif_bytes=sarif,
        html_bytes=html,
        excel_bytes=excel,
        pdf_bytes=pdf,
        extra=extra,
    )


__all__ = [
    "ReportBundle",
    "build_report",
    "build_reports",
    "build_sarif",
    "build_html",
    "build_excel",
    "build_pdf",
]
