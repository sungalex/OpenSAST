"""SQLAlchemy 엔진·세션 관리.

풀 크기는 `Settings.db_pool_size` 를 실제로 반영한다 (ADR-0006). 예전에는 이 값이
프로파일마다 정의되고 문서 표에도 실렸지만 `create_engine` 에 전달되지 않아
설정이 죽어 있었다.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from opensast.config import Settings, get_settings

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def _engine_kwargs(settings: Settings) -> dict:
    """드라이버에 맞는 `create_engine` 인자를 만든다.

    SQLite 는 QueuePool 을 쓰지 않으므로 pool_size/max_overflow 를 전달하면
    `TypeError` 가 난다. 따라서 서버형 DB 에만 풀 설정을 적용한다.
    """

    kwargs: dict = {"future": True, "pool_pre_ping": True}
    try:
        backend = make_url(settings.database_url).get_backend_name()
    except Exception:  # noqa: BLE001 - 잘못된 URL 은 create_engine 이 보고하게 둔다
        return kwargs
    if backend == "sqlite":
        return kwargs
    kwargs.update(
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_recycle=settings.db_pool_recycle_seconds,
    )
    return kwargs


def init_engine(settings: Settings | None = None) -> Engine:
    global _engine, _SessionFactory
    settings = settings or get_settings()
    _engine = create_engine(settings.database_url, **_engine_kwargs(settings))
    _SessionFactory = sessionmaker(
        bind=_engine, autoflush=False, autocommit=False, future=True
    )
    return _engine


def get_session() -> Session:
    if _SessionFactory is None:
        init_engine()
    assert _SessionFactory is not None
    return _SessionFactory()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
