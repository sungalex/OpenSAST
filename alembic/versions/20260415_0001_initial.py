"""initial schema — v0.4.0 시점의 전체 테이블 생성

Revision ID: 20260415_0001
Revises:
Create Date: 2026-04-15

이 마이그레이션은 SQLAlchemy 모델을 그대로 `metadata.create_all` 로 생성한다.
향후 스키마 변경은 `alembic revision --autogenerate` 로 새 리비전을 만든다.
"""
from __future__ import annotations

from alembic import op

from opensast.db.base import Base
# 모델 모듈을 import 해야 Base.metadata 에 테이블이 등록된다
import opensast.db.models  # noqa: F401

revision = "20260415_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind)
