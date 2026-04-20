"""리포트 생성 단위 테스트 (DB 모델 스텁 기반)."""

from __future__ import annotations

import json
from datetime import datetime

from opensast.db import models
from opensast.reports.excel import build_excel
from opensast.reports.html import build_html
from opensast.reports.sarif import build_sarif


def _scan() -> models.Scan:
    return models.Scan(
        id="t-scan",
        project_id=1,
        source_path="/tmp/sample",
        status="completed",
        started_at=datetime(2026, 4, 1, 9, 0),
        finished_at=datetime(2026, 4, 1, 9, 5),
        engine_stats={"opengrep": 1},
        mois_coverage={"SR1-1": 1},
    )


def _finding() -> models.Finding:
    row = models.Finding(
        scan_id="t-scan",
        finding_hash="deadbeef",
        rule_id="mois-sr1-1-python-sql-fstring",
        engine="opengrep",
        message="SQL 삽입 탐지",
        severity="HIGH",
        file_path="app/db.py",
        start_line=42,
        end_line=42,
        cwe_ids=["CWE-89"],
        mois_id="SR1-1",
        category="입력데이터 검증 및 표현",
        language="python",
        snippet="cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")",
        raw={},
    )
    return row


def test_build_sarif_is_valid_json() -> None:
    blob = build_sarif(_scan(), [_finding()])
    doc = json.loads(blob)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"].startswith("mois-")


def test_build_html_contains_korean_headings() -> None:
    html = build_html(_scan(), [_finding()]).decode("utf-8")
    assert "진단 결과 요약" in html
    assert "SR1-1" in html


def test_build_excel_has_three_sheets() -> None:
    blob = build_excel(_scan(), [_finding()])
    assert blob.startswith(b"PK")  # zip magic (xlsx)
    assert len(blob) > 1000
