"""DB 레포지토리 헬퍼.

API·Celery 태스크가 공용으로 사용하는 read/write 연산을 얇게 감싼다.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from aisast.config import Settings, get_settings
from aisast.db import models
from aisast.models import Finding as DomainFinding
from aisast.models import ScanResult
from aisast.utils.logging import get_logger

log = get_logger(__name__)


def ensure_bootstrap_admin(
    session: Session, *, settings: Settings | None = None
) -> models.User:
    """최초 기동 시 관리자 계정이 없으면 생성한다.

    이미 동일 이메일의 계정이 존재하면 아무것도 하지 않는다. 운영 환경에서는
    `AISAST_BOOTSTRAP_ADMIN_EMAIL` / `AISAST_BOOTSTRAP_ADMIN_PASSWORD` 환경변수로
    오버라이드하여 기본 자격증명 사용을 방지해야 한다.
    """

    from aisast.api.security import hash_password  # 순환 참조 회피

    settings = settings or get_settings()
    email = settings.bootstrap_admin_email
    existing = session.scalar(select(models.User).where(models.User.email == email))
    if existing is not None:
        return existing
    user = models.User(
        email=email,
        hashed_password=hash_password(settings.bootstrap_admin_password),
        display_name=settings.bootstrap_admin_display_name,
        role="admin",
        is_active=True,
    )
    session.add(user)
    session.flush()
    log.warning(
        "bootstrap admin created: %s (change the default password immediately)",
        email,
    )
    return user


def get_project_by_name(session: Session, name: str) -> models.Project | None:
    return session.scalar(select(models.Project).where(models.Project.name == name))


def create_project(
    session: Session,
    *,
    name: str,
    description: str = "",
    repo_url: str = "",
    default_language: str | None = None,
    owner_id: int | None = None,
) -> models.Project:
    project = models.Project(
        name=name,
        description=description,
        repo_url=repo_url,
        default_language=default_language,
        owner_id=owner_id,
    )
    session.add(project)
    session.flush()
    return project


def list_projects(session: Session) -> list[models.Project]:
    return list(session.scalars(select(models.Project).order_by(models.Project.id.desc())))


def create_scan_record(
    session: Session,
    *,
    scan_id: str,
    project_id: int,
    source_path: str,
) -> models.Scan:
    scan = models.Scan(
        id=scan_id,
        project_id=project_id,
        source_path=source_path,
        status="queued",
    )
    session.add(scan)
    session.flush()
    return scan


def mark_scan_running(session: Session, scan_id: str) -> None:
    scan = session.get(models.Scan, scan_id)
    if scan is None:
        return
    scan.status = "running"
    scan.started_at = datetime.utcnow()


def mark_scan_failed(session: Session, scan_id: str, *, error: str) -> None:
    scan = session.get(models.Scan, scan_id)
    if scan is None:
        return
    scan.status = "failed"
    scan.error = error
    scan.finished_at = datetime.utcnow()


def persist_scan_result(
    session: Session, scan_id: str, result: ScanResult
) -> None:
    import fnmatch

    scan = session.get(models.Scan, scan_id)
    if scan is None:
        return
    scan.status = "completed"
    scan.started_at = result.started_at
    scan.finished_at = result.finished_at
    scan.engine_stats = result.engine_stats
    scan.mois_coverage = result.mois_coverage

    suppressions = list(
        session.scalars(
            select(models.SuppressionRule).where(
                models.SuppressionRule.project_id == scan.project_id
            )
        )
    )

    def _is_suppressed(dom: DomainFinding) -> bool:
        for rule in suppressions:
            if rule.rule_id and rule.rule_id != dom.rule_id:
                continue
            if rule.kind == "rule" and rule.pattern == dom.rule_id:
                return True
            if rule.kind == "path" and fnmatch.fnmatch(
                dom.location.file_path, rule.pattern
            ):
                return True
            if rule.kind == "function" and rule.pattern in (
                dom.location.snippet or ""
            ):
                return True
        return False

    for dom in result.findings:
        row = _finding_from_domain(scan_id, dom)
        if _is_suppressed(dom):
            row.status = "excluded"
            row.status_reason = "auto-suppressed by project suppression rule"
        session.add(row)


def _finding_from_domain(scan_id: str, dom: DomainFinding) -> models.Finding:
    row = models.Finding(
        scan_id=scan_id,
        finding_hash=dom.finding_id,
        rule_id=dom.rule_id,
        engine=dom.engine,
        message=dom.message,
        severity=dom.severity.value,
        file_path=dom.location.file_path,
        start_line=dom.location.start_line,
        end_line=dom.location.end_line,
        cwe_ids=list(dom.cwe_ids),
        mois_id=dom.mois_id,
        category=dom.category,
        language=dom.language,
        snippet=dom.location.snippet,
        raw=dom.raw,
    )
    if dom.triage is not None:
        row.triage = models.TriageRecord(
            verdict=dom.triage.verdict,
            fp_probability=dom.triage.fp_probability,
            rationale=dom.triage.rationale,
            recommended_fix=dom.triage.recommended_fix,
            patched_code=dom.triage.patched_code,
            model=dom.triage.model,
        )
    return row


def list_scans_for_project(
    session: Session, project_id: int, *, limit: int = 50
) -> list[models.Scan]:
    return list(
        session.scalars(
            select(models.Scan)
            .where(models.Scan.project_id == project_id)
            .order_by(models.Scan.created_at.desc())
            .limit(limit)
        )
    )


def record_audit(
    session: Session,
    *,
    user_id: int | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip: str | None = None,
) -> models.AuditLog:
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        detail=detail or {},
        ip=ip,
    )
    session.add(entry)
    session.flush()
    return entry


def list_findings_for_scan(
    session: Session, scan_id: str, *, limit: int = 1000
) -> list[models.Finding]:
    return list(
        session.scalars(
            select(models.Finding)
            .where(models.Finding.scan_id == scan_id)
            .order_by(
                models.Finding.severity.asc(),
                models.Finding.file_path.asc(),
                models.Finding.start_line.asc(),
            )
            .limit(limit)
        )
    )
