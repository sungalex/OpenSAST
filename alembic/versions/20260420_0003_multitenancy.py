"""멀티테넌시 — Organization 모델 + organization_id FK.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-20

SQLite 호환성 주의:

- SQLite 에는 `ALTER TABLE ... ADD CONSTRAINT` 가 없다. FK 추가는 반드시
  `batch_alter_table` (테이블 복사·재생성) 안에서 해야 한다.
- `true` 리터럴 대신 파라미터 바인딩을 쓴다.
- 프로젝트 이름의 유일성 범위가 전역(`uq_projects_name`)에서 조직 스코프
  (`uq_project_org_name`)로 바뀐다.
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_SCOPED_TABLES = ("users", "projects", "rule_sets", "audit_logs")


def _columns(inspector: sa.Inspector, table: str) -> set[str]:
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "organizations" not in inspector.get_table_names():
        op.create_table(
            "organizations",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("slug", sa.String(120), unique=True, nullable=False),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("is_active", sa.Boolean, nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )

    existing = bind.execute(
        sa.text("SELECT COUNT(*) FROM organizations WHERE id = 1")
    ).scalar()
    if not existing:
        bind.execute(
            sa.text(
                "INSERT INTO organizations (id, slug, name, is_active) "
                "VALUES (1, :slug, :name, :active)"
            ),
            {"slug": "default-org", "name": "Default Organization", "active": True},
        )

    for table in _SCOPED_TABLES:
        if "organization_id" in _columns(inspector, table):
            continue
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("organization_id", sa.Integer, nullable=True))
            batch.create_foreign_key(
                f"fk_{table}_org", "organizations", ["organization_id"], ["id"]
            )
        op.execute(sa.text(f"UPDATE {table} SET organization_id = 1"))

    # 프로젝트 이름 유일성: 전역 → 조직 스코프
    project_uniques = {
        c["name"] for c in sa.inspect(bind).get_unique_constraints("projects")
    }
    with op.batch_alter_table("projects") as batch:
        if "uq_projects_name" in project_uniques:
            batch.drop_constraint("uq_projects_name", type_="unique")
        if "uq_project_org_name" not in project_uniques:
            batch.create_unique_constraint(
                "uq_project_org_name", ["organization_id", "name"]
            )


def downgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.drop_constraint("uq_project_org_name", type_="unique")
        batch.create_unique_constraint("uq_projects_name", ["name"])
    for table in reversed(_SCOPED_TABLES):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(f"fk_{table}_org", type_="foreignkey")
            batch.drop_column("organization_id")
    op.drop_table("organizations")
