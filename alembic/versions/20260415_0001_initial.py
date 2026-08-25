"""initial schema — v0.4.0 시점의 전체 테이블 생성 (동결).

Revision ID: 20260415_0001
Revises:
Create Date: 2026-04-15

**이 리비전은 명시적 DDL 로 동결되어 있다.**

예전에는 `Base.metadata.create_all(bind)` 를 호출했다. 그러면 이 리비전이
"현재 모델" 이라는 움직이는 표적을 따라가므로 두 가지가 깨진다.

1. 이후 리비전이 추가하는 인덱스·컬럼까지 여기서 미리 만들어져,
   `alembic upgrade head` 가 0002 에서 "index already exists" 로 **항상 실패**했다.
   (문서가 안내하는 프로덕션 스키마 경로가 처음부터 동작하지 않았다는 뜻이다.)
2. 이후 모든 모델 변경이 조용히 이 리비전에 흡수되어, 리비전 히스토리가
   아무것도 기록하지 못한다.

초기 리비전은 **그 시점의 스키마**를 고정해야 한다. 모델을 바꿀 때는
`alembic revision --autogenerate` 로 새 리비전을 만든다.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260415_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False),
        sa.Column("failed_attempts", sa.Integer, nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "rule_sets",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("name", sa.String(120), unique=True, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("enabled_engines", sa.JSON, nullable=False),
        sa.Column("include_rules", sa.JSON, nullable=False),
        sa.Column("exclude_rules", sa.JSON, nullable=False),
        sa.Column("min_severity", sa.String(16), nullable=False),
        sa.Column("is_default", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("repo_url", sa.String(500), nullable=False),
        sa.Column("default_language", sa.String(32), nullable=True),
        sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rule_set_id", sa.Integer, sa.ForeignKey("rule_sets.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # v0.4.0 시점: 프로젝트 이름이 전역 유일. 0003 에서 조직 스코프로 대체된다.
        sa.UniqueConstraint("name", name="uq_projects_name"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(32), primary_key=True, nullable=False),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("source_path", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("engine_stats", sa.JSON, nullable=False),
        sa.Column("mois_coverage", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("scan_id", sa.String(32), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("finding_hash", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("engine", sa.String(64), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("start_line", sa.Integer, nullable=False),
        sa.Column("end_line", sa.Integer, nullable=True),
        sa.Column("cwe_ids", sa.JSON, nullable=False),
        sa.Column("mois_id", sa.String(16), nullable=True),
        sa.Column("category", sa.String(120), nullable=True),
        sa.Column("language", sa.String(32), nullable=True),
        sa.Column("snippet", sa.Text, nullable=True),
        sa.Column("raw", sa.JSON, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("status_reason", sa.Text, nullable=True),
        sa.Column("reviewed_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "triage_records",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id"), unique=True, nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("fp_probability", sa.Integer, nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("recommended_fix", sa.Text, nullable=True),
        sa.Column("patched_code", sa.Text, nullable=True),
        sa.Column("model", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("pattern", sa.String(1024), nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "gate_policies",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id"), unique=True, nullable=False),
        sa.Column("max_high", sa.Integer, nullable=False),
        sa.Column("max_medium", sa.Integer, nullable=False),
        sa.Column("max_low", sa.Integer, nullable=False),
        sa.Column("max_new_high", sa.Integer, nullable=False),
        sa.Column("block_on_triage_fp_below", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "audit_logs",
        "gate_policies",
        "suppression_rules",
        "triage_records",
        "findings",
        "scans",
        "projects",
        "rule_sets",
        "users",
    ):
        op.drop_table(table)
