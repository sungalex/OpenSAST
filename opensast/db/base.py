"""SQLAlchemy declarative base.

**타임스탬프는 타임존 인식 UTC 로만 기록한다.**

예전에는 컬럼 기본값이 `datetime.utcnow` (naive) 였다. 컬럼 타입은
`DateTime(timezone=True)` 이므로 Postgres 에서는 `TIMESTAMPTZ` 인데, naive 값을
넣으면 **DB 세션 타임존으로 해석**된다. 서버 타임존이 UTC 가 아니면 저장된
시각이 그만큼 어긋나고, `audit_logs` 처럼 증적이 되는 타임스탬프에서는 그대로
문제가 된다 (KST 환경이면 최대 9시간).

`datetime.utcnow()` 는 Python 3.12 부터 deprecated 이기도 하다.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """타임존 인식 UTC 현재시각 — 모든 타임스탬프 컬럼의 단일 기본값."""

    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )
