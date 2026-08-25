"""Alembic 마이그레이션 체인 회귀 테스트.

`alembic upgrade head` 는 **처음부터 실패**하고 있었다. 리비전 0001 이
`Base.metadata.create_all()` 로 "현재 모델" 을 만들었기 때문에, 0002 가 추가하려는
인덱스가 이미 존재해 `index already exists` 로 죽었다. 문서가 안내하는 프로덕션
스키마 경로가 한 번도 동작하지 않았다는 뜻이다.

여기서 검증하는 것:

1. 빈 DB 에서 `upgrade head` 가 성공한다
2. 그 결과 스키마가 SQLAlchemy 모델과 일치한다 (드리프트 없음)
3. `downgrade base` → `upgrade head` 왕복이 성공한다
4. 0001 이 다시 `create_all` 로 돌아가지 않는다
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import sqlalchemy as sa

pytest.importorskip("alembic")

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _config(db_path: Path) -> Config:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_upgrade_head_on_empty_database(tmp_path: Path) -> None:
    db = tmp_path / "fresh.db"
    command.upgrade(_config(db), "head")
    insp = sa.inspect(sa.create_engine(f"sqlite:///{db}"))
    assert "findings" in insp.get_table_names()
    assert "organizations" in insp.get_table_names()


def test_migrated_schema_matches_models(tmp_path: Path) -> None:
    """마이그레이션 결과와 모델이 어긋나면 즉시 알아야 한다."""

    import opensast.db.models  # noqa: F401
    from opensast.db.base import Base

    db = tmp_path / "match.db"
    command.upgrade(_config(db), "head")
    insp = sa.inspect(sa.create_engine(f"sqlite:///{db}"))

    db_tables = set(insp.get_table_names()) - {"alembic_version"}
    model_tables = set(Base.metadata.tables)
    assert db_tables == model_tables

    for table in sorted(model_tables):
        db_cols = {c["name"] for c in insp.get_columns(table)}
        model_cols = set(Base.metadata.tables[table].columns.keys())
        assert db_cols == model_cols, f"{table} 컬럼 불일치"


def test_finding_uniqueness_index_exists(tmp_path: Path) -> None:
    db = tmp_path / "uq.db"
    command.upgrade(_config(db), "head")
    insp = sa.inspect(sa.create_engine(f"sqlite:///{db}"))
    idx = {i["name"]: i for i in insp.get_indexes("findings")}
    assert "uq_findings_scan_hash" in idx
    assert bool(idx["uq_findings_scan_hash"]["unique"]) is True


def test_downgrade_and_upgrade_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "roundtrip.db"
    cfg = _config(db)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    insp = sa.inspect(sa.create_engine(f"sqlite:///{db}"))
    assert "findings" in insp.get_table_names()


def test_initial_revision_is_frozen_ddl() -> None:
    """0001 이 `create_all` 로 되돌아가면 체인이 다시 깨진다."""

    source = (
        PROJECT_ROOT / "alembic" / "versions" / "20260415_0001_initial.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_all"
    ]
    assert calls == [], "초기 리비전은 명시적 DDL 로 동결되어야 한다"
    assert "op.create_table(" in source
