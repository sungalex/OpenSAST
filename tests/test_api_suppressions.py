"""Suppression 라우트 + persist_scan_result 자동 적용 테스트."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient


def test_create_list_delete_suppression(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
) -> None:
    pid = sample_project["id"]
    r = client.post(
        f"/api/projects/{pid}/suppressions",
        headers=admin_headers,
        json={
            "kind": "path",
            "pattern": "src/tests/**",
            "reason": "테스트 코드 허용",
        },
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]

    r = client.get(f"/api/projects/{pid}/suppressions", headers=admin_headers)
    assert any(s["id"] == sid for s in r.json())

    r = client.delete(
        f"/api/projects/{pid}/suppressions/{sid}", headers=admin_headers
    )
    assert r.status_code == 204
    r = client.get(f"/api/projects/{pid}/suppressions", headers=admin_headers)
    assert all(s["id"] != sid for s in r.json())


def test_invalid_kind_returns_422(
    client: TestClient,
    admin_headers: dict[str, str],
    sample_project: dict,
) -> None:
    r = client.post(
        f"/api/projects/{sample_project['id']}/suppressions",
        headers=admin_headers,
        json={"kind": "wildcard", "pattern": "x"},
    )
    assert r.status_code == 422


def test_persist_scan_result_auto_excludes_matching_findings(
    db_engine, sample_project: dict
) -> None:
    """suppression 이 등록된 상태에서 persist_scan_result 가 매칭 finding 의
    status 를 'excluded' 로 설정하는지 검증."""

    from sqlalchemy.orm import sessionmaker

    from aisast.db import models, repo
    from aisast.mois.catalog import Severity
    from aisast.models import (
        CodeLocation,
        Finding as DomainFinding,
        ScanResult,
    )

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        # 사전 준비: 스캔 row + suppression
        scan = models.Scan(
            id="autoexc00001",
            project_id=sample_project["id"],
            source_path="/tmp/x",
            status="queued",
            engine_stats={},
            mois_coverage={},
        )
        session.add(scan)
        session.add(
            models.SuppressionRule(
                project_id=sample_project["id"],
                kind="path",
                pattern="**/tests/**",
                reason="test code",
            )
        )
        session.add(
            models.SuppressionRule(
                project_id=sample_project["id"],
                kind="rule",
                pattern="mois-sr6-2-debug-print",
                rule_id="mois-sr6-2-debug-print",
            )
        )
        session.commit()

        # 도메인 Finding 두 개: 하나는 매칭, 하나는 매칭 안 됨
        result = ScanResult(
            scan_id="autoexc00001",
            target_root="/tmp/x",
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            findings=[
                DomainFinding(
                    rule_id="rule-a",
                    engine="opengrep",
                    message="in tests dir",
                    severity=Severity.HIGH,
                    location=CodeLocation(
                        file_path="src/tests/auth_test.py", start_line=1
                    ),
                ),
                DomainFinding(
                    rule_id="mois-sr6-2-debug-print",
                    engine="opengrep",
                    message="debug print",
                    severity=Severity.LOW,
                    location=CodeLocation(file_path="src/main.py", start_line=10),
                ),
                DomainFinding(
                    rule_id="rule-keep",
                    engine="opengrep",
                    message="real bug",
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path="src/api.py", start_line=42),
                ),
            ],
            engine_stats={"opengrep": 3},
            mois_coverage={},
        )
        repo.persist_scan_result(session, "autoexc00001", result)
        session.commit()

        rows = (
            session.query(models.Finding)
            .filter(models.Finding.scan_id == "autoexc00001")
            .all()
        )
        statuses = {row.rule_id: row.status for row in rows}
        # 경로 매칭 (path) — excluded
        assert statuses["rule-a"] == "excluded"
        # 룰 ID 매칭 — excluded
        assert statuses["mois-sr6-2-debug-print"] == "excluded"
        # 매칭 없음 — new
        assert statuses["rule-keep"] == "new"
    finally:
        session.close()
