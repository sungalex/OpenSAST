"""감사 로그 라우트 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_audit_requires_admin(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    r = client.get("/api/admin/audit", headers=analyst_headers)
    assert r.status_code == 403


def test_login_creates_audit_entry(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """admin_headers 픽스처가 로그인 호출을 발생시키므로 이미 audit 항목이 있어야."""

    r = client.get(
        "/api/admin/audit", headers=admin_headers, params={"action": "auth.login"}
    )
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) >= 1
    assert all(row["action"] == "auth.login" for row in rows)


def test_failed_login_creates_audit_entry(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    client.post(
        "/api/auth/login",
        json={"email": "ghost@example.com", "password": "anything"},
    )
    r = client.get(
        "/api/admin/audit",
        headers=admin_headers,
        params={"action": "auth.login_failed"},
    )
    rows = r.json()
    assert any(row["action"] == "auth.login_failed" for row in rows)


def test_status_change_creates_audit_entry(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=admin_headers).json()
    fid = rows[0]["id"]
    client.post(
        f"/api/findings/{fid}/status",
        headers=admin_headers,
        json={"status": "confirmed", "reason": "audited"},
    )
    r = client.get(
        "/api/admin/audit",
        headers=admin_headers,
        params={"action": "finding.status_change"},
    )
    audit = r.json()
    assert any(
        e["target_id"] == str(fid) and e["detail"]["to"] == "confirmed"
        for e in audit
    )


def test_suppression_create_delete_audit(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
) -> None:
    pid = sample_project["id"]
    r = client.post(
        f"/api/projects/{pid}/suppressions",
        headers=admin_headers,
        json={"kind": "rule", "pattern": "x", "reason": "y"},
    )
    sid = r.json()["id"]
    client.delete(f"/api/projects/{pid}/suppressions/{sid}", headers=admin_headers)

    r = client.get("/api/admin/audit", headers=admin_headers)
    actions = {row["action"] for row in r.json()}
    assert "suppression.create" in actions
    assert "suppression.delete" in actions
