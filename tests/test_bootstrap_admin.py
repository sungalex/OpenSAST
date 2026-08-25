"""부트스트랩 관리자 생성 로직 검증 (SQLite 인메모리)."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from opensast.api.security import verify_password
from opensast.config import Settings
from opensast.db import repo
from opensast.db.base import Base
from opensast.db.models import User

from tests._credentials import make_test_password


def _make_session():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, future=True)
    return Session()


def test_bootstrap_admin_creates_once() -> None:
    password = make_test_password("boot-a")
    settings = Settings(
        bootstrap_admin_email="bootstrap@example.com",
        bootstrap_admin_password=password,
    )
    session = _make_session()
    try:
        user = repo.ensure_bootstrap_admin(session, settings=settings)
        session.commit()
        assert user.role == "admin"
        assert user.is_active is True
        assert verify_password(password, user.hashed_password)

        # 이미 존재 → 동일 인스턴스 재사용, 새로 생성되지 않음
        again = repo.ensure_bootstrap_admin(session, settings=settings)
        assert again.id == user.id
        assert session.query(User).count() == 1
    finally:
        session.close()


def test_bootstrap_admin_does_not_overwrite_existing() -> None:
    password = make_test_password("boot-b")
    settings = Settings(
        bootstrap_admin_email="preexisting@example.com",
        bootstrap_admin_password=password,
    )
    session = _make_session()
    try:
        session.add(
            User(
                email="preexisting@example.com",
                hashed_password="not-a-real-hash",
                display_name="Original",
                role="analyst",
                is_active=True,
            )
        )
        session.commit()

        user = repo.ensure_bootstrap_admin(session, settings=settings)
        assert user.hashed_password == "not-a-real-hash"
        assert user.role == "analyst"
    finally:
        session.close()
