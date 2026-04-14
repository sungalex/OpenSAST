"""데이터베이스 모델.

- User: API 인증 사용자 (RBAC: admin/analyst/viewer)
- Project: 진단 대상 프로젝트
- Scan: 단일 진단 실행 레코드
- Finding: 정규화된 탐지 결과
- TriageRecord: LLM 오탐 판정 기록
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aisast.db.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    default_language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all,delete-orphan"
    )


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), nullable=False
    )
    source_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    engine_stats: Mapped[dict] = mapped_column(JSON, default=dict)
    mois_coverage: Mapped[dict] = mapped_column(JSON, default=dict)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all,delete-orphan"
    )


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    finding_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    engine: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    mois_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    triage: Mapped["TriageRecord | None"] = relationship(
        back_populates="finding", uselist=False, cascade="all,delete-orphan"
    )


class TriageRecord(Base, TimestampMixin):
    __tablename__ = "triage_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id"), nullable=False, unique=True
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    fp_probability: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    recommended_fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    patched_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(64), default="")

    finding: Mapped[Finding] = relationship(back_populates="triage")
