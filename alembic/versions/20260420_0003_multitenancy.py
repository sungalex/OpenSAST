"""멀티테넌시 — Organization 모델 + organization_id FK.

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("slug", sa.String(120), unique=True, nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "INSERT INTO organizations (id, slug, name, is_active) "
        "VALUES (1, 'default-org', 'Default Organization', true)"
    )
    for table in ("users", "projects", "rule_sets", "audit_logs"):
        op.add_column(table, sa.Column("organization_id", sa.Integer, nullable=True))
        op.create_foreign_key(
            f"fk_{table}_org", table, "organizations", ["organization_id"], ["id"]
        )
        op.execute(f"UPDATE {table} SET organization_id = 1")


def downgrade() -> None:
    for table in ("audit_logs", "rule_sets", "projects", "users"):
        op.drop_constraint(f"fk_{table}_org", table, type_="foreignkey")
        op.drop_column(table, "organization_id")
    op.drop_table("organizations")
