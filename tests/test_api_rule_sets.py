"""체커 그룹(RuleSet) 라우트 통합 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_create_rule_set_admin_only(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/rule-sets",
        headers=analyst_headers,
        json={"name": "x", "enabled_engines": [], "min_severity": "LOW"},
    )
    assert r.status_code == 403


def test_create_and_list_rule_set(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/rule-sets",
        headers=admin_headers,
        json={
            "name": "java-strict",
            "description": "Java only",
            "enabled_engines": ["opengrep", "spotbugs"],
            "include_rules": [],
            "exclude_rules": ["mois-sr6-2-debug-print"],
            "min_severity": "MEDIUM",
            "is_default": False,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "java-strict"
    assert body["min_severity"] == "MEDIUM"
    assert body["enabled_engines"] == ["opengrep", "spotbugs"]

    r = client.get("/api/rule-sets", headers=admin_headers)
    assert r.status_code == 200
    assert any(rs["name"] == "java-strict" for rs in r.json())


def test_duplicate_name_returns_409(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    payload = {"name": "dup-rs", "enabled_engines": [], "min_severity": "LOW"}
    r1 = client.post("/api/rule-sets", headers=admin_headers, json=payload)
    assert r1.status_code == 201
    r2 = client.post("/api/rule-sets", headers=admin_headers, json=payload)
    assert r2.status_code == 409


def test_default_singleton_enforcement(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """is_default=true 인 그룹이 두 번째 생기면 기존 default 가 해제되어야."""

    client.post(
        "/api/rule-sets",
        headers=admin_headers,
        json={
            "name": "first-default",
            "is_default": True,
            "enabled_engines": [],
            "min_severity": "LOW",
        },
    )
    client.post(
        "/api/rule-sets",
        headers=admin_headers,
        json={
            "name": "second-default",
            "is_default": True,
            "enabled_engines": [],
            "min_severity": "LOW",
        },
    )
    rows = client.get("/api/rule-sets", headers=admin_headers).json()
    defaults = [r for r in rows if r["is_default"]]
    assert len(defaults) == 1
    assert defaults[0]["name"] == "second-default"


def test_delete_default_rejected(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/rule-sets",
        headers=admin_headers,
        json={
            "name": "to-default",
            "is_default": True,
            "enabled_engines": [],
            "min_severity": "LOW",
        },
    )
    rid = r.json()["id"]
    r = client.delete(f"/api/rule-sets/{rid}", headers=admin_headers)
    assert r.status_code == 400


def test_delete_non_default(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/rule-sets",
        headers=admin_headers,
        json={
            "name": "deletable",
            "enabled_engines": [],
            "min_severity": "LOW",
        },
    )
    rid = r.json()["id"]
    r = client.delete(f"/api/rule-sets/{rid}", headers=admin_headers)
    assert r.status_code == 204
