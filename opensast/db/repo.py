"""DB 레포지토리 헬퍼.

API·Celery 태스크가 공용으로 사용하는 read/write 연산을 얇게 감싼다.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from opensast.config import Settings, get_settings
from opensast.db import models
from opensast.db.base import utcnow
from opensast.models import Finding as DomainFinding
from opensast.models import ScanResult
from opensast.utils.logging import get_logger

log = get_logger(__name__)


#: 타임존 인식 UTC — 정의는 `opensast.db.base` 한 곳에 있다.
_utcnow = utcnow


def ensure_bootstrap_admin(
    session: Session, *, settings: Settings | None = None
) -> models.User:
    """최초 기동 시 관리자 계정이 없으면 생성한다.

    이미 동일 이메일의 계정이 존재하면 아무것도 하지 않는다. 운영 환경에서는
    `OPENSAST_BOOTSTRAP_ADMIN_EMAIL` / `OPENSAST_BOOTSTRAP_ADMIN_PASSWORD` 환경변수로
    오버라이드하여 기본 자격증명 사용을 방지해야 한다.
    """

    from opensast.api.security import hash_password  # 순환 참조 회피

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
    organization_id: int | None = None,
) -> models.Project:
    project = models.Project(
        name=name,
        description=description,
        repo_url=repo_url,
        default_language=default_language,
        owner_id=owner_id,
        organization_id=organization_id,
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
    scan.started_at = _utcnow()


def mark_scan_failed(session: Session, scan_id: str, *, error: str) -> None:
    scan = session.get(models.Scan, scan_id)
    if scan is None:
        return
    scan.status = "failed"
    scan.error = error
    scan.finished_at = _utcnow()


def persist_scan_result(
    session: Session, scan_id: str, result: ScanResult
) -> int:
    """스캔 결과를 저장한다. **멱등**하다 (H-5).

    Celery 태스크는 `autoretry_for=(Exception,)` 로 재시도되므로, 저장 도중
    워커가 죽으면 같은 스캔이 다시 실행된다. 이미 저장된 `finding_hash` 는
    건너뛰어 Finding 이 2~3배로 쌓이는 것을 막는다. DB 에도
    `uq_findings_scan_hash` 유니크 제약이 걸려 있어 경쟁 상태에서도 안전하다.

    Returns: 이번 호출에서 새로 삽입한 Finding 개수.
    """

    import fnmatch

    scan = session.get(models.Scan, scan_id)
    if scan is None:
        return 0
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

    existing_hashes = set(
        session.scalars(
            select(models.Finding.finding_hash).where(
                models.Finding.scan_id == scan_id
            )
        )
    )
    inserted = 0
    seen: set[str] = set()
    for dom in result.findings:
        if dom.finding_id in existing_hashes or dom.finding_id in seen:
            continue
        seen.add(dom.finding_id)
        row = _finding_from_domain(scan_id, dom)
        if _is_suppressed(dom):
            row.status = "excluded"
            row.status_reason = "auto-suppressed by project suppression rule"
        session.add(row)
        inserted += 1
    if existing_hashes:
        log.info(
            "scan %s: %d findings already persisted, inserted %d new",
            scan_id,
            len(existing_hashes),
            inserted,
        )
    return inserted


def _finding_from_domain(scan_id: str, dom: DomainFinding) -> models.Finding:
    """도메인 → ORM 변환 (구현은 `opensast.db.mapping` 단일 출처)."""

    from opensast.db.mapping import finding_to_orm

    return finding_to_orm(scan_id, dom)


def list_scans_for_project(
    session: Session, project_id: int, *, limit: int = 50
) -> list[models.Scan]:
    return list(
        session.scalars(
            select(models.Scan)
            .options(selectinload(models.Scan.findings))
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


def count_findings_for_scan(session: Session, scan_id: str) -> int:
    return (
        session.scalar(
            select(func.count(models.Finding.id)).where(
                models.Finding.scan_id == scan_id
            )
        )
        or 0
    )


def list_findings_for_scan(
    session: Session,
    scan_id: str,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[models.Finding]:
    """스캔의 Finding 을 severity(HIGH→MEDIUM→LOW) 순으로 반환한다.

    `limit=None` 이면 전부 반환한다. 예전에는 기본 1000 건에서 **조용히**
    잘렸는데, 진단 도구에서 그 절단은 커버리지 누락으로 직결된다 (M-3).
    호출자는 `count_findings_for_scan()` 으로 전체 건수를 확인할 수 있다.
    """

    stmt = (
        select(models.Finding)
        .options(selectinload(models.Finding.triage))
        .where(models.Finding.scan_id == scan_id)
        .order_by(
            models.severity_order(),
            models.Finding.file_path.asc(),
            models.Finding.start_line.asc(),
        )
        .offset(offset)
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return list(session.scalars(stmt))
