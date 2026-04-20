"""Alembic 마이그레이션 환경.

OpenSAST 는 `opensast.config.get_settings()` 로부터 DB URL 과 메타데이터를 가져온다.
마이그레이션 CLI:

    alembic upgrade head          # 최신 리비전까지 적용
    alembic revision --autogenerate -m "..."  # 모델 diff 기반 새 리비전 생성
    alembic downgrade -1          # 이전 리비전으로 되돌림
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from opensast.config import get_settings
from opensast.db.base import Base

# Alembic config
config = context.config

# 로깅 설정 파일
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# OpenSAST 설정에서 DB URL 주입
_settings = get_settings()
config.set_main_option("sqlalchemy.url", _settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """오프라인(SQL 파일 생성) 모드."""

    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """실제 DB 에 연결해 적용하는 온라인 모드."""

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
