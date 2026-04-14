"""auto_migrate() 자동 컬럼 추가 검증."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool


def _fresh_engine():
    return create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )


def test_auto_migrate_creates_all_tables_on_empty_db() -> None:
    from aisast.db.migrate import auto_migrate

    engine = _fresh_engine()
    auto_migrate(engine)
    inspector = inspect(engine)
    expected = {
        "users",
        "projects",
        "scans",
        "findings",
        "triage_records",
        "rule_sets",
        "suppression_rules",
        "gate_policies",
        "audit_logs",
    }
    assert expected.issubset(set(inspector.get_table_names()))


def test_auto_migrate_adds_missing_column_to_existing_table() -> None:
    """기존 테이블에서 누락된 컬럼이 자동으로 ADD COLUMN 되는지."""

    from aisast.db.base import Base
    from aisast.db.migrate import auto_migrate

    engine = _fresh_engine()
    # 1) 모든 테이블을 정상 생성
    Base.metadata.create_all(engine)

    # 2) findings.status 컬럼을 강제로 제거 (ALTER 대상으로 만들기 위한 시뮬레이션)
    with engine.begin() as conn:
        # SQLite 는 DROP COLUMN 을 지원하지 않으므로, 새 임시 테이블로 복제
        conn.execute(text("DROP TABLE findings"))
        conn.execute(
            text(
                """
                CREATE TABLE findings (
                    id INTEGER PRIMARY KEY,
                    scan_id VARCHAR NOT NULL,
                    finding_hash VARCHAR(32) NOT NULL,
                    rule_id VARCHAR(200) NOT NULL,
                    engine VARCHAR(64) NOT NULL,
                    message TEXT NOT NULL,
                    severity VARCHAR(16) NOT NULL,
                    file_path VARCHAR(1024) NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER,
                    cwe_ids JSON,
                    mois_id VARCHAR(16),
                    category VARCHAR(120),
                    language VARCHAR(32),
                    snippet TEXT,
                    raw JSON,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
                """
            )
        )

    inspector = inspect(engine)
    cols_before = {c["name"] for c in inspector.get_columns("findings")}
    assert "status" not in cols_before

    # 3) auto_migrate 가 누락된 status/status_reason/reviewed_by/reviewed_at 추가
    applied = auto_migrate(engine)
    assert any("status" in stmt for stmt in applied)

    inspector = inspect(engine)
    cols_after = {c["name"] for c in inspector.get_columns("findings")}
    assert "status" in cols_after
    assert "status_reason" in cols_after
    assert "reviewed_by" in cols_after
    assert "reviewed_at" in cols_after


def test_auto_migrate_idempotent() -> None:
    """두 번 실행해도 추가 ALTER 가 발생하지 않아야 한다."""

    from aisast.db.migrate import auto_migrate

    engine = _fresh_engine()
    auto_migrate(engine)
    second_run = auto_migrate(engine)
    assert second_run == []
