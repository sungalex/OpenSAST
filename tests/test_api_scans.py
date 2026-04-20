"""스캔 라우트 통합 테스트 (큐잉, diff, source viewer)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient


def test_queue_scan_returns_202(
    client: TestClient, admin_headers: dict[str, str], sample_project: dict
) -> None:
    r = client.post(
        "/api/scans",
        headers=admin_headers,
        json={
            "project_id": sample_project["id"],
            "source_path": "/tmp/foo",
            "enable_second_pass": False,
            "enable_triage": False,
        },
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert body["project_id"] == sample_project["id"]
    assert body["source_path"] == "/tmp/foo"


def test_queue_scan_unknown_project_404(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/scans",
        headers=admin_headers,
        json={"project_id": 99999, "source_path": "/tmp/x"},
    )
    assert r.status_code == 404


def test_get_scan_and_list_for_project(
    client: TestClient, admin_headers: dict[str, str], sample_scan_with_findings: dict
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    pid = sample_scan_with_findings["project_id"]

    r = client.get(f"/api/scans/{sid}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["id"] == sid

    r = client.get(f"/api/scans/project/{pid}", headers=admin_headers)
    assert r.status_code == 200
    assert any(s["id"] == sid for s in r.json())


def test_get_unknown_scan_404(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.get("/api/scans/no-such-scan", headers=admin_headers)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_diff_with_no_previous_scan_returns_all_as_new(
    db_engine,
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    sid = sample_scan_with_findings["scan_id"]
    r = client.get(f"/api/scans/{sid}/diff", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["base_scan_id"] is None
    assert body["head_scan_id"] == sid
    # base 가 없으면 head 의 모든 finding 이 신규로 분류된다
    assert body["summary"]["new"] == 4
    assert body["summary"]["resolved"] == 0
    assert body["persistent"] == 0
    # 신규 HIGH 2건 (sample_scan_with_findings 시드 데이터)
    assert body["summary"]["new_high"] == 2


def test_diff_with_previous_scan_classifies_new_resolved(
    db_engine,
    client: TestClient,
    admin_headers: dict[str, str],
    sample_scan_with_findings: dict,
) -> None:
    """직전 스캔과 비교 — 같은 finding_hash 는 persistent, head 에만 있는 건 new."""

    from sqlalchemy.orm import sessionmaker

    from opensast.db import models

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        # 새 스캔 생성 (첫 번째와 같은 프로젝트, 더 늦은 시각)
        head = models.Scan(
            id="head00000001",
            project_id=sample_scan_with_findings["project_id"],
            source_path="/tmp/test-source",
            status="completed",
            started_at=datetime(2026, 4, 16, 10, 0, tzinfo=timezone.utc),
            finished_at=datetime(2026, 4, 16, 10, 5, tzinfo=timezone.utc),
            engine_stats={},
            mois_coverage={},
        )
        session.add(head)
        session.flush()

        # head 에는: hash-0000 (persistent) + new-0001 (신규)
        session.add(
            models.Finding(
                scan_id=head.id,
                finding_hash="hash-0000",
                rule_id="rule-x",
                engine="opengrep",
                severity="HIGH",
                message="persistent",
                file_path="src/db.py",
                start_line=10,
                cwe_ids=["CWE-89"],
                mois_id="SR1-1",
                category="입력데이터 검증 및 표현",
                language="python",
                snippet=None,
                raw={},
                status="new",
            )
        )
        session.add(
            models.Finding(
                scan_id=head.id,
                finding_hash="new-0001",
                rule_id="rule-y",
                engine="opengrep",
                severity="HIGH",
                message="newly introduced",
                file_path="src/api.py",
                start_line=22,
                cwe_ids=["CWE-79"],
                mois_id="SR1-3",
                category="입력데이터 검증 및 표현",
                language="python",
                snippet=None,
                raw={},
                status="new",
            )
        )
        session.commit()

        r = client.get(f"/api/scans/{head.id}/diff", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # base 자동 선택 → sample_scan_with_findings (testscan0001)
        assert body["base_scan_id"] == "testscan0001"
        assert body["summary"]["new"] == 1  # new-0001
        assert body["summary"]["resolved"] >= 1  # 이전 스캔에만 있던 hash들
        assert body["summary"]["new_high"] == 1
    finally:
        session.close()


# ---------------------------------------------------------------------------
# source viewer
# ---------------------------------------------------------------------------


def test_source_viewer_path_traversal_blocked(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
    db_engine,
    tmp_path: Path,
) -> None:
    """`../../etc/passwd` 같은 경로 탈출이 차단되는지."""

    from sqlalchemy.orm import sessionmaker

    from opensast.db import models

    # 실 파일이 있는 임시 소스 루트
    src_root = tmp_path / "scan-src"
    src_root.mkdir()
    (src_root / "ok.py").write_text("print('ok')\n")

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        scan = models.Scan(
            id="srcscan00001",
            project_id=sample_project["id"],
            source_path=str(src_root),
            status="completed",
            engine_stats={},
            mois_coverage={},
        )
        session.add(scan)
        session.commit()
    finally:
        session.close()

    # 정상 경로
    r = client.get(
        "/api/scans/srcscan00001/source",
        params={"path": "ok.py"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["truncated"] is False
    assert "print" in body["content"]

    # 경로 탈출 시도 → 400
    r = client.get(
        "/api/scans/srcscan00001/source",
        params={"path": "../../etc/passwd"},
        headers=admin_headers,
    )
    assert r.status_code == 400


def test_source_viewer_missing_directory_410(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
    db_engine,
) -> None:
    from sqlalchemy.orm import sessionmaker

    from opensast.db import models

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        scan = models.Scan(
            id="goneScan0001",
            project_id=sample_project["id"],
            source_path="/nonexistent/cleaned-up",
            status="completed",
            engine_stats={},
            mois_coverage={},
        )
        session.add(scan)
        session.commit()
    finally:
        session.close()

    r = client.get(
        "/api/scans/goneScan0001/source",
        params={"path": "any.py"},
        headers=admin_headers,
    )
    assert r.status_code == 410
