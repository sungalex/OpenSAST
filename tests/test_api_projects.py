"""프로젝트 라우트 통합 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_create_and_list_project(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/projects",
        headers=admin_headers,
        json={"name": "p1", "description": "first"},
    )
    assert r.status_code == 201, r.text
    pid = r.json()["id"]

    r = client.get("/api/projects", headers=admin_headers)
    assert r.status_code == 200
    names = [p["name"] for p in r.json()]
    assert "p1" in names

    r = client.get(f"/api/projects/{pid}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["description"] == "first"


def test_duplicate_project_name_409(
    client: TestClient, admin_headers: dict[str, str], sample_project: dict
) -> None:
    r = client.post(
        "/api/projects",
        headers=admin_headers,
        json={"name": sample_project["name"]},
    )
    assert r.status_code == 409


def test_get_unknown_project_404(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.get("/api/projects/999999", headers=admin_headers)
    assert r.status_code == 404


def test_analyst_can_create_project(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    """analyst 도 프로젝트 생성 가능 (require_role 미적용 라우트)."""

    r = client.post(
        "/api/projects",
        headers=analyst_headers,
        json={"name": "analyst-proj"},
    )
    assert r.status_code == 201
