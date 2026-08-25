"""Add composite indexes for performance.

Revision ID: 0002
Revises: 20260415_0001
Create Date: 2026-04-16

인덱스 생성은 **멱등**하다. 0001 이 `create_all` 이던 시절에 만들어진 DB 나,
개발용 `auto_migrate` 로 만들어진 DB 를 alembic 아래로 편입할 때
(`alembic stamp base && alembic upgrade head`) 이름 충돌로 실패하지 않도록 한다.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "20260415_0001"
branch_labels = None
depends_on = None

_INDEXES: list[tuple[str, str, list[str]]] = [
    ("ix_findings_scan_severity_status", "findings", ["scan_id", "severity", "status"]),
    ("ix_findings_mois_id", "findings", ["mois_id"]),
    ("ix_findings_finding_hash", "findings", ["finding_hash"]),
    ("ix_scans_project_status_created", "scans", ["project_id", "status", "created_at"]),
    ("ix_audit_logs_user_created", "audit_logs", ["user_id", "created_at"]),
    ("ix_suppression_rules_project_kind", "suppression_rules", ["project_id", "kind"]),
    ("ix_triage_records_finding_id", "triage_records", ["finding_id"]),
]


def _existing(inspector: sa.Inspector, table: str) -> set[str]:
    try:
        return {ix["name"] for ix in inspector.get_indexes(table)}
    except sa.exc.NoSuchTableError:  # pragma: no cover - 방어
        return set()


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for name, table, columns in _INDEXES:
        if name not in _existing(inspector, table):
            op.create_index(name, table, columns)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for name, table, _ in reversed(_INDEXES):
        if name in _existing(inspector, table):
            op.drop_index(name, table_name=table)
