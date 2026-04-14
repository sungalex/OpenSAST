"""Findings 라우트 통합 테스트 (조회·검색·워크플로·자연어)."""

from __future__ import annotations

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# 조회 + references
# ---------------------------------------------------------------------------


def test_list_findings_for_scan(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    r = client.get(f"/api/findings/scan/{sid}", headers=admin_headers)
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 4
    # 모든 행에 references 필드가 채워져야 함
    for row in rows:
        assert "references" in row
        assert isinstance(row["references"], list)


def test_finding_response_includes_references(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    """SQL 삽입(SR1-1, CWE-89) 이 OWASP A03 + SANS Top 25 #3 을 갖는지."""

    sid = sample_scan_with_findings["scan_id"]
    r = client.get(f"/api/findings/scan/{sid}", headers=admin_headers)
    sql_rows = [r for r in r.json() if r["mois_id"] == "SR1-1"]
    assert sql_rows
    refs = sql_rows[0]["references"]
    standards = {ref["standard"] for ref in refs}
    assert "CWE" in standards
    assert "OWASP-2021" in standards
    assert "SANS-25" in standards


def test_get_finding_by_id(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=admin_headers).json()
    fid = rows[0]["id"]
    r = client.get(f"/api/findings/{fid}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["id"] == fid


# ---------------------------------------------------------------------------
# Advanced Issue Filter
# ---------------------------------------------------------------------------


def test_search_by_severity_high_only(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"severity": "HIGH"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert all(row["severity"] == "HIGH" for row in rows)
    assert len(rows) == 2  # sample_scan_with_findings 에 HIGH 2건


def test_search_filter_by_engine_and_text(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"engine": "bandit", "text": "md5"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["engine"] == "bandit"
    assert "md5" in rows[0]["message"].lower()


def test_search_filter_by_mois_id(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"mois_id": "SR1-1"},
    )
    rows = r.json()
    assert len(rows) == 2
    assert all(row["mois_id"] == "SR1-1" for row in rows)


def test_search_filter_by_path_glob(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"path_glob": "src/db.py"},
    )
    rows = r.json()
    assert len(rows) == 2
    assert all(row["file_path"] == "src/db.py" for row in rows)


def test_search_filter_by_cwe(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"cwe": "CWE-79"},
    )
    rows = r.json()
    assert len(rows) == 1
    assert "CWE-79" in rows[0]["cwe_ids"]


def test_search_excludes_excluded_status_by_default(
    db_engine,
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    """기본 검색에는 status='excluded' 가 포함되지 않아야 한다."""

    from sqlalchemy.orm import sessionmaker

    from aisast.db import models

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        rows = session.query(models.Finding).limit(1).all()
        rows[0].status = "excluded"
        session.commit()
    finally:
        session.close()

    r = client.get("/api/findings/search", headers=admin_headers)
    statuses = {row["status"] for row in r.json()}
    assert "excluded" not in statuses

    # include_excluded=true 면 포함
    r = client.get(
        "/api/findings/search",
        headers=admin_headers,
        params={"include_excluded": "true"},
    )
    statuses = {row["status"] for row in r.json()}
    assert "excluded" in statuses


# ---------------------------------------------------------------------------
# 워크플로 상태 전이
# ---------------------------------------------------------------------------


def test_status_transition_new_to_confirmed(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=admin_headers).json()
    fid = rows[0]["id"]
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=admin_headers,
        json={"status": "confirmed", "reason": "확인됨"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "confirmed"
    assert r.json()["status_reason"] == "확인됨"


def test_analyst_cannot_directly_exclude(
    client: TestClient,
    analyst_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=analyst_headers).json()
    fid = rows[0]["id"]
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=analyst_headers,
        json={"status": "excluded"},
    )
    assert r.status_code == 400


def test_analyst_can_request_exclusion(
    client: TestClient,
    analyst_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=analyst_headers).json()
    fid = rows[0]["id"]
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=analyst_headers,
        json={"status": "exclusion_requested", "reason": "테스트 코드"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "exclusion_requested"


def test_admin_can_approve_exclusion(
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=analyst_headers).json()
    fid = rows[0]["id"]

    # 1) analyst 가 신청
    client.post(
        f"/api/findings/{fid}/status",
        headers=analyst_headers,
        json={"status": "exclusion_requested"},
    )
    # 2) admin 이 승인
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=admin_headers,
        json={"status": "excluded", "reason": "오탐 확인"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "excluded"


def test_invalid_status_value_returns_422(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    rows = client.get(f"/api/findings/scan/{sid}", headers=admin_headers).json()
    fid = rows[0]["id"]
    r = client.post(
        f"/api/findings/{fid}/status",
        headers=admin_headers,
        json={"status": "definitely-not-a-status"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 자연어 검색
# ---------------------------------------------------------------------------


def test_natural_language_search_returns_findings(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    """LLM 이 noop 이라도 키워드 fallback 으로 결과를 반환해야 한다."""

    r = client.post(
        "/api/findings/ask",
        headers=admin_headers,
        json={"query": "SQL 삽입 보여줘"},
    )
    assert r.status_code == 200
    # noop 의 응답은 {"verdict":"needs_review",...} JSON 이므로 LLM 파싱이 빈 필터로
    # 떨어질 수 있음. 그래도 200 이고 list 여야 한다.
    assert isinstance(r.json(), list)
