"""MOIS catalog · 리포트 다운로드 · health 라우트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "app" in body


def test_mois_items_returns_49_with_references(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.get("/api/mois/items", headers=admin_headers)
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 49
    # 모든 항목에 references 필드가 채워져야 함
    for item in items:
        assert isinstance(item.get("references"), list)
    # SQL 삽입(SR1-1)에 OWASP/SANS/PCI 모두 매핑
    sr1_1 = next(item for item in items if item["id"] == "SR1-1")
    standards = {ref["standard"] for ref in sr1_1["references"]}
    assert {"CWE", "OWASP-2021", "SANS-25", "PCI-DSS-4.0"}.issubset(standards)


def test_reports_sarif_html_excel(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]

    r = client.get(f"/api/reports/{sid}/sarif", headers=admin_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/sarif+json")
    assert b'"version": "2.1.0"' in r.content

    r = client.get(f"/api/reports/{sid}/html", headers=admin_headers)
    assert r.status_code == 200
    assert "진단 결과" in r.text or "보안약점" in r.text

    r = client.get(f"/api/reports/{sid}/excel", headers=admin_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    # XLSX = ZIP magic
    assert r.content[:2] == b"PK"


def test_reports_unknown_scan_404(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.get("/api/reports/no-such/sarif", headers=admin_headers)
    assert r.status_code == 404
