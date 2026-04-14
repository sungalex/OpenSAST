"""대시보드 통계 라우트 통합 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_overview_basic(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get("/api/dashboard/overview", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    totals = body["totals"]
    assert totals["projects"] == 1
    assert totals["scans"] == 1
    assert totals["findings"] == 4
    assert totals["high"] == 2
    assert totals["medium"] == 1
    assert totals["low"] == 1
    assert body["latest_scan"] is not None
    assert body["latest_scan"]["id"] == sample_scan_with_findings["scan_id"]


def test_overview_status_counts_default_new(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    body = client.get("/api/dashboard/overview", headers=admin_headers).json()
    assert body["status_counts"].get("new") == 4


def test_top_rules_orders_by_count(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get("/api/dashboard/top-rules?limit=10", headers=admin_headers)
    body = r.json()
    assert "top" in body
    # SQL 삽입 룰이 가장 많이 등장 (2건) — 1위
    assert body["top"][0]["count"] >= body["top"][-1]["count"]
    rule_ids = {row["rule_id"] for row in body["top"]}
    assert "mois-sr1-1-python-sql-fstring" in rule_ids


def test_mois_coverage_matches_seed(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get("/api/dashboard/mois-coverage", headers=admin_headers)
    body = r.json()
    assert body["total_items"] == 49
    assert body["covered_items"] == 3  # SR1-1, SR1-3, SR2-4
    by_id = {item["mois_id"]: item for item in body["items"]}
    assert by_id["SR1-1"]["count"] == 2
    assert by_id["SR1-3"]["count"] == 1
    assert by_id["SR2-4"]["count"] == 1
    # 미커버 항목
    assert by_id["SR3-1"]["count"] == 0
    assert by_id["SR3-1"]["covered"] is False


def test_category_distribution(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/dashboard/category-distribution", headers=admin_headers
    )
    body = r.json()
    cats = {c["name"]: c["count"] for c in body["categories"]}
    assert cats["입력데이터 검증 및 표현"] == 3
    assert cats["보안기능"] == 1


def test_trends_endpoint_returns_timeline(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get("/api/dashboard/trends?days=30", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["days"] == 30
    assert isinstance(body["timeline"], list)


def test_dashboard_requires_auth(client: TestClient) -> None:
    r = client.get("/api/dashboard/overview")
    assert r.status_code == 401
