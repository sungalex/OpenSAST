"""CI/CD 빌드 게이트 라우트 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_upsert_policy_admin_only(
    client: TestClient,
    analyst_headers: dict[str, str],
    sample_project: dict,
) -> None:
    r = client.put(
        "/api/gate/policy",
        headers=analyst_headers,
        json={"project_id": sample_project["id"]},
    )
    assert r.status_code == 403


def test_upsert_then_get_policy(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
) -> None:
    pid = sample_project["id"]
    r = client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 0,
            "max_medium": 10,
            "max_low": 100,
            "max_new_high": 0,
            "block_on_triage_fp_below": 30,
            "enabled": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["max_high"] == 0
    assert body["max_medium"] == 10
    pid_assigned = body["id"]

    # upsert: 같은 프로젝트로 다시 호출 → 같은 row 업데이트
    r2 = client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 5,
            "max_medium": 20,
            "max_low": 200,
            "max_new_high": 1,
            "block_on_triage_fp_below": 30,
            "enabled": True,
        },
    )
    assert r2.json()["id"] == pid_assigned
    assert r2.json()["max_high"] == 5

    r3 = client.get(f"/api/gate/policy/{pid}", headers=admin_headers)
    assert r3.status_code == 200
    assert r3.json()["max_high"] == 5


def test_check_passes_when_under_thresholds(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    pid = sample_scan_with_findings["project_id"]
    client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 100,
            "max_medium": 100,
            "max_low": 100,
            "max_new_high": 100,
            "block_on_triage_fp_below": 30,
            "enabled": True,
        },
    )
    r = client.post(
        "/api/gate/check",
        headers=admin_headers,
        json={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is True


def test_check_blocks_when_over_thresholds(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    pid = sample_scan_with_findings["project_id"]
    client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 0,
            "max_medium": 0,
            "max_low": 0,
            "max_new_high": 0,
            "block_on_triage_fp_below": 30,
            "enabled": True,
        },
    )
    r = client.post(
        "/api/gate/check",
        headers=admin_headers,
        json={"project_id": pid},
    )
    body = r.json()
    assert body["passed"] is False
    assert any("HIGH" in r for r in body["reasons"])
    assert body["counts"]["HIGH"] == 2


def test_check_excludes_excluded_findings(
    db_engine,
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    """status='excluded' 인 finding 은 게이트 카운트에서 빠진다."""

    from sqlalchemy.orm import sessionmaker

    from opensast.db import models

    pid = sample_scan_with_findings["project_id"]
    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        # 모든 HIGH 를 excluded 로
        session.query(models.Finding).filter(
            models.Finding.severity == "HIGH"
        ).update({"status": "excluded"})
        session.commit()
    finally:
        session.close()

    client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 0,
            "max_medium": 100,
            "max_low": 100,
            "max_new_high": 0,
            "block_on_triage_fp_below": 30,
            "enabled": True,
        },
    )
    r = client.post(
        "/api/gate/check",
        headers=admin_headers,
        json={"project_id": pid},
    )
    body = r.json()
    # HIGH 카운트가 0 이라 통과해야 한다
    assert body["counts"]["HIGH"] == 0
    assert body["passed"] is True


def test_check_disabled_policy_passes(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    pid = sample_scan_with_findings["project_id"]
    client.put(
        "/api/gate/policy",
        headers=admin_headers,
        json={
            "project_id": pid,
            "max_high": 0,
            "max_medium": 0,
            "max_low": 0,
            "max_new_high": 0,
            "block_on_triage_fp_below": 30,
            "enabled": False,
        },
    )
    r = client.post(
        "/api/gate/check",
        headers=admin_headers,
        json={"project_id": pid},
    )
    assert r.json()["passed"] is True
