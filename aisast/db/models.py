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
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    default_language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    rule_set_id: Mapped[int | None] = mapped_column(
        ForeignKey("rule_sets.id"), nullable=True
    )

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
    # Sparrow 스타일 이슈 상태 워크플로:
    #   new: 미확인 (분석 직후)
    #   confirmed: 개발자가 실제 취약점으로 확인
    #   exclusion_requested: 오탐/허용으로 간주, 관리자 승인 대기
    #   excluded: 관리자 승인 완료 — 카운트에서 제외
    #   fixed: 조치 완료
    #   rejected: 관리자 거부 — new 로 복귀하기 전 단계
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

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


class RuleSet(Base, TimestampMixin):
    """체커 그룹 — 프로젝트별 사용할 룰 화이트/블랙리스트.

    Sparrow 의 '체커 그룹' 과 동일 개념. 엔진 허용 목록과 특정 규칙 ID 포함/제외 목록을
    관리하며, 프로젝트가 참조하도록 FK 를 추가한다.
    """

    __tablename__ = "rule_sets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled_engines: Mapped[list[str]] = mapped_column(JSON, default=list)
    include_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclude_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    min_severity: Mapped[str] = mapped_column(String(16), default="LOW")
    is_default: Mapped[bool] = mapped_column(default=False, nullable=False)


class SuppressionRule(Base, TimestampMixin):
    """경로·함수·룰 기반 탐지 제외 규칙."""

    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # path | function | rule
    pattern: Mapped[str] = mapped_column(String(1024), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class GatePolicy(Base, TimestampMixin):
    """CI/CD 이관 제어(빌드 게이트) 정책.

    프로젝트별로 단일 정책을 보유한다. 임계값을 초과하면 `/api/gate/check` 가 실패를
    반환해 CI 파이프라인이 머지를 차단할 수 있다.
    """

    __tablename__ = "gate_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), unique=True, nullable=False
    )
    max_high: Mapped[int] = mapped_column(Integer, default=0)
    max_medium: Mapped[int] = mapped_column(Integer, default=50)
    max_low: Mapped[int] = mapped_column(Integer, default=500)
    max_new_high: Mapped[int] = mapped_column(Integer, default=0)
    block_on_triage_fp_below: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)


class AuditLog(Base):
    """사용자 감사 로그."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
