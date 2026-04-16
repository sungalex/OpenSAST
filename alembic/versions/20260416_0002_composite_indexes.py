"""Add composite indexes for performance.

Revision ID: 0002
Revises: 20260415_0001
Create Date: 2026-04-16
"""

from alembic import op

revision = "0002"
down_revision = "20260415_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_findings_scan_severity_status", "findings", ["scan_id", "severity", "status"])
    op.create_index("ix_findings_mois_id", "findings", ["mois_id"])
    op.create_index("ix_findings_finding_hash", "findings", ["finding_hash"])
    op.create_index("ix_scans_project_status_created", "scans", ["project_id", "status", "created_at"])
    op.create_index("ix_audit_logs_user_created", "audit_logs", ["user_id", "created_at"])
    op.create_index("ix_suppression_rules_project_kind", "suppression_rules", ["project_id", "kind"])


def downgrade() -> None:
    op.drop_index("ix_suppression_rules_project_kind", "suppression_rules")
    op.drop_index("ix_audit_logs_user_created", "audit_logs")
    op.drop_index("ix_scans_project_status_created", "scans")
    op.drop_index("ix_findings_finding_hash", "findings")
    op.drop_index("ix_findings_mois_id", "findings")
    op.drop_index("ix_findings_scan_severity_status", "findings")
