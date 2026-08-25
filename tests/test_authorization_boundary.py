"""인가 경계 회귀 테스트 (ADR-0005).

이 파일이 검증하는 실패 모드는 전부 실제로 존재했던 것이다.

- 라우트가 `ActorContext` 를 빠뜨려 조직 필터가 "전체 통과" 로 평가됨
- `viewer` 가 스캔을 큐잉할 수 있었음 (RBAC 표와 불일치)
- 대시보드가 조직과 무관하게 전역 집계를 반환
- SSE 엔드포인트에 인증이 아예 없었음
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from opensast.services.base import ActorContext, BaseService
from tests._credentials import ORG_USER_PASSWORD


# ---------------------------------------------------------------------------
# 서비스 계약
# ---------------------------------------------------------------------------


def test_service_requires_actor(db_session) -> None:
    """actor 없이 서비스를 만들 수 없어야 한다 — 라우트 누락이 즉시 드러난다."""

    with pytest.raises(TypeError, match="ActorContext"):
        BaseService(db_session, None)  # type: ignore[arg-type]


def test_org_filter_defaults_to_block(db_session) -> None:
    """조직이 다르면 필터가 통과시키지 않아야 한다 (기본값 차단)."""

    from opensast.db import models

    svc = BaseService(db_session, ActorContext(user=None, organization_id=7))
    clause = svc._org_filter(models.Project)
    assert "organization_id" in str(clause)
    # system 컨텍스트만 전체 통과
    sys_svc = BaseService(db_session, ActorContext.system(reason="test"))
    assert str(sys_svc._org_filter(models.Project)) == "true"


# ---------------------------------------------------------------------------
# RBAC — 스캔 실행은 쓰기 역할만
# ---------------------------------------------------------------------------


def test_viewer_cannot_queue_scan(
    client: TestClient,
    viewer_headers: dict[str, str],
    sample_project: dict,
    allowed_scan_root,
) -> None:
    r = client.post(
        "/api/scans",
        headers=viewer_headers,
        json={
            "project_id": sample_project["id"],
            "source_path": str(allowed_scan_root),
        },
    )
    assert r.status_code == 403, r.text


def test_viewer_cannot_change_finding_status(
    client: TestClient,
    viewer_headers: dict[str, str],
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    fid = client.get(f"/api/findings/scan/{sid}", headers=admin_headers).json()[0]["id"]
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=viewer_headers,
        json={"status": "confirmed"},
    )
    assert r.status_code == 403, r.text


def test_analyst_can_queue_scan(
    client: TestClient,
    analyst_headers: dict[str, str],
    admin_headers: dict[str, str],
    sample_project: dict,
    allowed_scan_root,
) -> None:
    r = client.post(
        "/api/scans",
        headers=analyst_headers,
        json={
            "project_id": sample_project["id"],
            "source_path": str(allowed_scan_root),
        },
    )
    assert r.status_code == 202, r.text


def test_viewer_cannot_create_rule_set(
    client: TestClient, viewer_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/rule-sets",
        headers=viewer_headers,
        json={"name": "rs", "enabled_engines": ["opengrep"]},
    )
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# 경로 허용 목록 — 워커 호스트 임의 파일 읽기 차단
# ---------------------------------------------------------------------------


def test_scan_path_outside_allowlist_rejected(
    client: TestClient, admin_headers: dict[str, str], sample_project: dict
) -> None:
    r = client.post(
        "/api/scans",
        headers=admin_headers,
        json={"project_id": sample_project["id"], "source_path": "/etc"},
    )
    assert r.status_code == 403, r.text
    assert "허용되지 않은" in r.json()["detail"]


def test_scan_path_traversal_out_of_allowlist_rejected(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
    allowed_scan_root,
) -> None:
    escaped = str(allowed_scan_root / ".." / ".." / ".." / "etc")
    r = client.post(
        "/api/scans",
        headers=admin_headers,
        json={"project_id": sample_project["id"], "source_path": escaped},
    )
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# SSE 인증
# ---------------------------------------------------------------------------


def test_sse_requires_authentication(
    client: TestClient, sample_scan_with_findings: dict
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    r = client.get(f"/api/scans/{sid}/events")
    assert r.status_code == 401, r.text


def test_sse_accepts_authenticated_request(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    r = client.get(f"/api/scans/{sid}/events", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert "completed" in r.text


def test_sse_unknown_scan_is_404(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.get("/api/scans/does-not-exist/events", headers=admin_headers)
    assert r.status_code == 404, r.text


# ---------------------------------------------------------------------------
# 조직 격리 (멀티테넌시)
# ---------------------------------------------------------------------------


@pytest.fixture
def two_orgs(db_engine, client: TestClient, admin_headers: dict[str, str]):
    """조직 A/B 와 각 조직 소속 admin 사용자, 그리고 A 소속 스캔을 만든다."""

    from datetime import datetime, timezone

    from opensast.api.security import hash_password
    from opensast.db import models

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        org_a = models.Organization(slug="org-a", name="A", is_active=True)
        org_b = models.Organization(slug="org-b", name="B", is_active=True)
        session.add_all([org_a, org_b])
        session.flush()

        users = {}
        for tag, org in (("a", org_a), ("b", org_b)):
            u = models.User(
                email=f"{tag}@org.local",
                hashed_password=hash_password(ORG_USER_PASSWORD),
                display_name=tag,
                role="admin",
                is_active=True,
                organization_id=org.id,
            )
            session.add(u)
            users[tag] = u
        session.flush()

        project_a = models.Project(
            name="proj-a", description="", repo_url="", organization_id=org_a.id
        )
        session.add(project_a)
        session.flush()

        scan_a = models.Scan(
            id="orgascan001",
            project_id=project_a.id,
            source_path="/tmp/org-a",
            status="completed",
            started_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            finished_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            engine_stats={"opengrep": 1},
            mois_coverage={"SR1-1": 1},
        )
        session.add(scan_a)
        session.flush()
        session.add(
            models.Finding(
                scan_id=scan_a.id,
                finding_hash="orga-0001",
                rule_id="r",
                engine="opengrep",
                message="org A only",
                severity="HIGH",
                file_path="a.py",
                start_line=1,
                cwe_ids=["CWE-89"],
                mois_id="SR1-1",
                raw={},
                status="new",
            )
        )
        session.commit()
        return {
            "scan_a": scan_a.id,
            "project_a": project_a.id,
            "org_a": org_a.id,
            "org_b": org_b.id,
            "user_a": users["a"].id,
            "user_b": users["b"].id,
        }
    finally:
        session.close()


def _org_headers(client: TestClient, tag: str) -> dict[str, str]:
    r = client.post(
        "/api/auth/login",
        json={"email": f"{tag}@org.local", "password": ORG_USER_PASSWORD},
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_cross_org_scan_is_not_visible(client: TestClient, two_orgs: dict) -> None:
    headers_b = _org_headers(client, "b")
    r = client.get(f"/api/scans/{two_orgs['scan_a']}", headers=headers_b)
    assert r.status_code == 404, r.text


def test_own_org_scan_is_visible(client: TestClient, two_orgs: dict) -> None:
    headers_a = _org_headers(client, "a")
    r = client.get(f"/api/scans/{two_orgs['scan_a']}", headers=headers_a)
    assert r.status_code == 200, r.text


def test_cross_org_findings_are_not_visible(
    client: TestClient, two_orgs: dict
) -> None:
    headers_b = _org_headers(client, "b")
    r = client.get(f"/api/findings/scan/{two_orgs['scan_a']}", headers=headers_b)
    assert r.status_code == 404, r.text

    r = client.get("/api/findings/search", headers=headers_b)
    assert r.status_code == 200, r.text
    assert all(f["scan_id"] != two_orgs["scan_a"] for f in r.json())


def test_cross_org_source_viewer_is_blocked(
    client: TestClient, two_orgs: dict
) -> None:
    headers_b = _org_headers(client, "b")
    r = client.get(
        f"/api/scans/{two_orgs['scan_a']}/source",
        headers=headers_b,
        params={"path": "a.py"},
    )
    assert r.status_code == 404, r.text


def test_cross_org_reports_are_blocked(client: TestClient, two_orgs: dict) -> None:
    headers_b = _org_headers(client, "b")
    r = client.get(f"/api/reports/{two_orgs['scan_a']}/sarif", headers=headers_b)
    assert r.status_code == 404, r.text


def test_dashboard_is_org_scoped(client: TestClient, two_orgs: dict) -> None:
    headers_a = _org_headers(client, "a")
    headers_b = _org_headers(client, "b")

    a = client.get("/api/dashboard/overview", headers=headers_a).json()
    b = client.get("/api/dashboard/overview", headers=headers_b).json()

    assert a["totals"]["findings"] == 1
    assert b["totals"]["findings"] == 0
    assert b["totals"]["scans"] == 0
    assert b["latest_scan"] is None


def test_cross_org_project_scan_list_is_blocked(
    client: TestClient, two_orgs: dict
) -> None:
    headers_b = _org_headers(client, "b")
    r = client.get(f"/api/scans/project/{two_orgs['project_a']}", headers=headers_b)
    assert r.status_code == 404, r.text


def test_organizations_list_requires_auth(client: TestClient) -> None:
    assert client.get("/api/organizations").status_code == 401


# ---------------------------------------------------------------------------
# 감사 로그 조직 격리 (ADR-0005 후속 — 최초 반영에서 누락됐던 라우트)
# ---------------------------------------------------------------------------


def test_audit_log_records_organization(
    client: TestClient, db_engine, two_orgs: dict
) -> None:
    """로그인 감사 로그에 조직이 귀속돼야 한다.

    예전에는 `repo.record_audit` 이 `organization_id` 를 아예 채우지 않아
    모든 행이 NULL 이었다. 그러면 조회에 조직 필터를 걸 근거 자체가 없다.
    """

    from opensast.db import models

    _org_headers(client, "a")  # 로그인 → auth.login 감사 기록

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        rows = [
            r
            for r in session.query(models.AuditLog).all()
            if r.user_id == two_orgs["user_a"]
        ]
        assert rows, "조직 A 사용자의 감사 로그가 없다"
        assert all(r.organization_id == two_orgs["org_a"] for r in rows)
    finally:
        session.close()


def test_cross_org_audit_logs_are_not_visible(
    client: TestClient, two_orgs: dict
) -> None:
    """조직 A 의 admin 이 조직 B 의 감사 로그를 읽을 수 없어야 한다."""

    headers_a = _org_headers(client, "a")
    _org_headers(client, "b")  # 조직 B 감사 로그 생성

    r = client.get("/api/admin/audit", headers=headers_a, params={"limit": 1000})
    assert r.status_code == 200, r.text
    user_ids = {row["user_id"] for row in r.json()}
    assert two_orgs["user_b"] not in user_ids
    assert two_orgs["user_a"] in user_ids


def test_audit_requires_admin_role(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    assert client.get("/api/admin/audit", headers=analyst_headers).status_code == 403


# ---------------------------------------------------------------------------
# 조직 레지스트리 열거 차단
# ---------------------------------------------------------------------------


def test_org_user_sees_only_own_organization(
    client: TestClient, two_orgs: dict
) -> None:
    """조직 소속 사용자는 다른 테넌트를 열거할 수 없어야 한다."""

    r = client.get("/api/organizations", headers=_org_headers(client, "a"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert [o["id"] for o in body] == [two_orgs["org_a"]]


def test_cross_org_organization_detail_is_404(
    client: TestClient, two_orgs: dict
) -> None:
    """존재 여부를 노출하지 않도록 403 이 아니라 404 로 막는다."""

    r = client.get(
        f"/api/organizations/{two_orgs['org_b']}", headers=_org_headers(client, "a")
    )
    assert r.status_code == 404


def test_org_scoped_admin_cannot_create_organization(
    client: TestClient, two_orgs: dict
) -> None:
    """테넌트 admin 은 새 테넌트를 만들 수 없다 — 플랫폼 관리자 권한이다."""

    r = client.post(
        "/api/organizations",
        headers=_org_headers(client, "a"),
        json={"slug": "org-c", "name": "C"},
    )
    assert r.status_code == 403


def test_platform_admin_sees_all_organizations(
    client: TestClient, admin_headers: dict[str, str], two_orgs: dict
) -> None:
    """조직 미지정 admin(= 플랫폼 관리자)은 전체 레지스트리를 본다."""

    r = client.get("/api/organizations", headers=admin_headers)
    assert r.status_code == 200, r.text
    ids = {o["id"] for o in r.json()}
    assert {two_orgs["org_a"], two_orgs["org_b"]} <= ids


def test_organization_create_rejects_missing_fields(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """예전에는 `payload["slug"]` 가 KeyError 로 500 을 냈다."""

    r = client.post("/api/organizations", headers=admin_headers, json={"name": "x"})
    assert r.status_code == 422
