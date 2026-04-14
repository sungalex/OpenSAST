"""기동 시 누락 컬럼 자동 추가.

운영 환경에서는 Alembic 마이그레이션을 사용하는 것이 정석이지만, 본 도구의
초기 단계에서는 모델 변경이 잦아 이를 따라잡기 어렵다. 본 헬퍼는 SQLAlchemy
inspector 로 모델과 실제 DB 컬럼을 비교해 누락된 컬럼을 자동 ALTER TABLE 한다.

지원 대상:
  * 신규 컬럼 추가 (NULLABLE 또는 default 가 있는 경우만)
  * 신규 테이블 (Base.metadata.create_all 로 처리)

지원하지 않음:
  * 컬럼 이름 변경, 타입 변경, 컬럼 삭제
  * 인덱스/제약조건 변경

이러한 변경이 필요해지면 Alembic 도입 시점이다.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Column, inspect, text
from sqlalchemy.engine import Engine

from aisast.db.base import Base
from aisast.utils.logging import get_logger

log = get_logger(__name__)


def auto_migrate(engine: Engine) -> list[str]:
    """모델과 실제 DB 를 비교해 누락 컬럼을 ALTER TABLE 로 추가."""

    Base.metadata.create_all(engine)  # 새 테이블 생성
    inspector = inspect(engine)
    applied: list[str] = []
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            ddl = _column_ddl(table.name, column)
            if ddl is None:
                log.warning(
                    "skipping column %s.%s — cannot derive safe DDL",
                    table.name,
                    column.name,
                )
                continue
            with engine.begin() as conn:
                conn.execute(text(ddl))
            applied.append(ddl)
            log.warning("auto-migrate: %s", ddl)
    return applied


def _column_ddl(table_name: str, column: Column[Any]) -> str | None:
    """단일 ALTER TABLE … ADD COLUMN 문 생성.

    - 새 컬럼은 반드시 NULL 허용 또는 default 가 있어야 한다 (기존 row 호환).
    - JSON / Text / Integer / String / DateTime / Boolean 만 지원.
    """

    sql_type = _python_type_to_sql(column)
    if sql_type is None:
        return None
    nullable = column.nullable
    default_clause = ""
    if column.default is not None and getattr(column.default, "is_scalar", False):
        val = column.default.arg
        if isinstance(val, bool):
            default_clause = f" DEFAULT {'TRUE' if val else 'FALSE'}"
        elif isinstance(val, (int, float)):
            default_clause = f" DEFAULT {val}"
        elif isinstance(val, str):
            escaped = val.replace("'", "''")
            default_clause = f" DEFAULT '{escaped}'"
    elif column.server_default is not None:
        default_clause = f" DEFAULT {column.server_default.arg}"
    elif not nullable:
        # NOT NULL 추가 시 기본값이 필요. 안전한 기본값 추정.
        if "VARCHAR" in sql_type or "TEXT" in sql_type:
            default_clause = " DEFAULT ''"
        elif "INT" in sql_type:
            default_clause = " DEFAULT 0"
        elif "BOOLEAN" in sql_type:
            default_clause = " DEFAULT FALSE"
        elif "JSON" in sql_type:
            default_clause = " DEFAULT '{}'"
        else:
            return None
    null_clause = "" if nullable else " NOT NULL"
    # NOTE: `IF NOT EXISTS` 는 SQLite 가 지원하지 않는다. inspector 로 누락 컬럼을
    # 사전 검사하므로 절을 생략해도 동일하게 안전하다. (Postgres/MySQL/SQLite 공통)
    return (
        f'ALTER TABLE "{table_name}" '
        f'ADD COLUMN "{column.name}" {sql_type}{default_clause}{null_clause}'
    )


def _python_type_to_sql(column: Column[Any]) -> str | None:
    """Postgres 호환 컬럼 타입 문자열."""

    sql_type = column.type
    name = sql_type.__class__.__name__.upper()
    length = getattr(sql_type, "length", None)
    if name in ("STRING", "VARCHAR"):
        return f"VARCHAR({length})" if length else "VARCHAR"
    if name == "TEXT":
        return "TEXT"
    if name == "INTEGER":
        return "INTEGER"
    if name == "BIGINTEGER":
        return "BIGINT"
    if name == "BOOLEAN":
        return "BOOLEAN"
    if name == "DATETIME":
        return "TIMESTAMP WITH TIME ZONE"
    if name == "DATE":
        return "DATE"
    if name == "JSON":
        return "JSON"
    return None
