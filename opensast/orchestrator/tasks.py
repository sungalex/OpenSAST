"""Celery 태스크 정의.

웹 API는 스캔 작업을 큐잉하고, 워커가 `run_scan_task` / `clone_and_scan_task`
를 수행한다. 결과는 PostgreSQL에 저장되며, 비동기 상태는 Celery 자체의
backend로 추적한다.

**재시도 정책 (H-5)**

예전에는 `autoretry_for=(Exception,)` 로 모든 예외를 재시도했다. 결정적 실패
(잘못된 경로, 파싱 오류)까지 2시간짜리 스캔을 3번 반복했고, 태스크가 이미
스캔을 `failed` 로 기록한 뒤 재시도돼 상태가 어긋났다. 이제는

- **일시적 오류만** 재시도한다 (DB/브로커 연결 등).
- 스캔 상태는 **재시도가 끝난 뒤에만** `failed` 로 기록한다.
- 결과 저장(`persist_scan_result`)은 멱등하므로, 재시도가 Finding 을
  중복 삽입하지 않는다.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, OperationalError

from opensast.config import get_settings
from opensast.db import models, repo
from opensast.db.session import session_scope
from opensast.orchestrator.celery_app import celery_app
from opensast.orchestrator.pipeline import ScanOptions, run_scan
from opensast.utils.logging import get_logger
from opensast.utils.paths import ensure_dir
from opensast.utils.subprocess import run_capture

log = get_logger(__name__)

#: 재시도할 가치가 있는 일시적 오류. 그 밖의 예외는 즉시 실패 처리한다.
TRANSIENT_ERRORS = (OperationalError, DBAPIError, ConnectionError, TimeoutError)

_TASK_DEFAULTS = dict(
    bind=True,
    autoretry_for=TRANSIENT_ERRORS,
    max_retries=2,
    retry_backoff=True,
    retry_backoff_max=120,
    acks_late=True,
)


def _is_final_attempt(task) -> bool:
    """이번 시도가 마지막인지 — 마지막에만 DB 에 실패를 확정한다."""

    retries = getattr(task.request, "retries", 0) or 0
    max_retries = task.max_retries or 0
    return retries >= max_retries


def _fail_scan(task, scan_id: str, error: str) -> None:
    if not _is_final_attempt(task):
        log.info("scan %s 실패했으나 재시도 예정 — 상태 유지", scan_id)
        return
    with session_scope() as session:
        repo.mark_scan_failed(session, scan_id, error=error[:2000])


@celery_app.task(name="opensast.run_scan", **_TASK_DEFAULTS)
def run_scan_task(
    self,
    scan_id: str,
    source_path: str,
    enable_second_pass: bool = True,
    enable_triage: bool = True,
    language_hint: str | None = None,
) -> dict:
    """큐잉된 스캔을 실제 실행한다."""

    settings = get_settings()
    root = Path(source_path).resolve()

    # 워커 측 2차 방어선: API 가 검증했더라도 큐 메시지를 그대로 믿지 않는다.
    allowed = settings.allowed_source_roots()
    if not any(_contained(root, r) for r in allowed):
        error = f"허용되지 않은 스캔 경로: {root}"
        log.error("scan %s rejected: %s", scan_id, error)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error=error)
        return {"scan_id": scan_id, "status": "rejected"}

    options = ScanOptions(
        enable_second_pass=enable_second_pass,
        enable_triage=enable_triage,
        language_hint=language_hint,
    )
    with session_scope() as session:
        repo.mark_scan_running(session, scan_id)

    self.update_state(state="PROGRESS", meta={"phase": "scanning", "progress": 0})

    try:
        result = run_scan(root, options=options)
    except TRANSIENT_ERRORS as exc:
        log.warning("scan %s transient failure: %s", scan_id, exc)
        _fail_scan(self, scan_id, str(exc))
        raise
    except SoftTimeLimitExceeded:
        log.error("scan %s exceeded soft time limit", scan_id)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error="시간 제한 초과")
        raise
    except Exception as exc:  # noqa: BLE001 - 결정적 실패는 재시도하지 않는다
        log.exception("scan %s failed: %s", scan_id, exc)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error=str(exc))
        return {"scan_id": scan_id, "status": "failed", "error": str(exc)}

    self.update_state(state="PROGRESS", meta={"phase": "persisting", "progress": 90})

    with session_scope() as session:
        inserted = repo.persist_scan_result(session, scan_id, result)
    return {
        "scan_id": scan_id,
        "total_findings": len(result.findings),
        "inserted": inserted,
        "engine_stats": result.engine_stats,
        "notes": list(result.notes),
    }


@celery_app.task(name="opensast.clone_and_scan", **_TASK_DEFAULTS)
def clone_and_scan_task(
    self,
    scan_id: str,
    git_url: str,
    branch: str | None = None,
    enable_second_pass: bool = True,
    enable_triage: bool = True,
    language_hint: str | None = None,
) -> dict:
    """Git URL 을 작업 디렉터리에 clone 후 스캔한다.

    `settings.work_dir/sources/<scan_id>` 에 체크아웃하며, 성공·실패·예외 어느
    경로로 빠져나가든 `finally` 에서 디렉터리를 정리한다 (O7).
    """

    settings = get_settings()
    scan_root = Path(settings.work_dir) / "sources" / scan_id
    ensure_dir(scan_root.parent)

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    # `--` 로 옵션과 인자를 분리해 URL 이 옵션으로 해석되는 것을 막는다.
    cmd += ["--", git_url, str(scan_root)]

    with session_scope() as session:
        repo.mark_scan_running(session, scan_id)

    try:
        clone = run_capture(cmd, timeout=600)
        if clone.returncode != 0:
            error = (clone.stderr or clone.stdout or "").strip()[-2000:]
            log.error("git clone failed for %s: %s", scan_id, error)
            with session_scope() as session:
                repo.mark_scan_failed(
                    session, scan_id, error=f"git clone failed: {error}"
                )
            return {"scan_id": scan_id, "status": "failed"}

        options = ScanOptions(
            enable_second_pass=enable_second_pass,
            enable_triage=enable_triage,
            language_hint=language_hint,
        )
        result = run_scan(scan_root, options=options)

        with session_scope() as session:
            scan_row = session.get(models.Scan, scan_id)
            if scan_row is not None:
                scan_row.source_path = str(scan_root)
            inserted = repo.persist_scan_result(session, scan_id, result)
    except TRANSIENT_ERRORS as exc:
        log.warning("clone_and_scan %s transient failure: %s", scan_id, exc)
        _fail_scan(self, scan_id, str(exc))
        raise
    except SoftTimeLimitExceeded:
        log.error("clone_and_scan %s exceeded soft time limit", scan_id)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error="시간 제한 초과")
        raise
    except Exception as exc:  # noqa: BLE001
        log.exception("clone_and_scan %s crashed: %s", scan_id, exc)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error=str(exc))
        return {"scan_id": scan_id, "status": "failed", "error": str(exc)}
    finally:
        # 스캔 결과는 DB 에 있으므로 체크아웃은 어느 경로에서도 정리한다.
        shutil.rmtree(scan_root, ignore_errors=True)

    return {
        "scan_id": scan_id,
        "total_findings": len(result.findings),
        "inserted": inserted,
        "engine_stats": result.engine_stats,
        "notes": list(result.notes),
    }


@celery_app.task(
    name="opensast.triage_batch",
    bind=True,
    autoretry_for=TRANSIENT_ERRORS,
    max_retries=1,
    retry_backoff=True,
    acks_late=True,
)
def triage_batch_task(
    self,
    scan_id: str,
    finding_ids: list[int] | None = None,
) -> dict:
    """특정 스캔(또는 finding 목록)에 대해 배치 LLM triage를 실행."""

    from opensast.db.mapping import apply_triage, finding_to_domain
    from opensast.llm.triage import Triager
    from opensast.models import Finding as DomainFinding

    with session_scope() as session:
        stmt = select(models.Finding)
        if finding_ids:
            stmt = stmt.where(models.Finding.id.in_(finding_ids))
        else:
            stmt = stmt.where(
                models.Finding.scan_id == scan_id,
                models.Finding.status != "excluded",
            )
        rows = list(session.scalars(stmt))

        # DB -> 도메인 변환. row.id 를 도메인 finding_id 로 넘겨 zip 순서 의존을
        # 없앤다 (행 순서가 아니라 id 로 되돌린다).
        by_id: dict[str, models.Finding] = {}
        domain_findings: list[DomainFinding] = []
        for r in rows:
            dom = finding_to_domain(r)
            # 이전 판정은 지우고 새로 받는다 (캐시 히트 여부는 Triager 가 판단)
            dom.triage = None
            by_id[dom.finding_id] = r
            domain_findings.append(dom)

        triager = Triager()
        triager.triage(domain_findings)
        report = triager.last_report

        for dom in domain_findings:
            row = by_id.get(dom.finding_id)
            if row is None or dom.triage is None:
                continue
            apply_triage(row, dom.triage)

    return {
        "scan_id": scan_id,
        "triaged": report.triaged,
        "cached": report.cached,
        "failed": report.failed,
        "truncated": report.truncated,
        "cache_enabled": report.cache_enabled,
    }


@celery_app.task(name="opensast.requeue_orphan_scans")
def requeue_orphan_scans(max_age_minutes: int = 30) -> dict:
    """브로커 발행 실패로 `queued` 에 갇힌 스캔을 회수한다 (M-7).

    서비스는 DB 커밋 후 큐에 발행한다. 그 사이에 브로커가 죽으면 스캔 행만 남고
    아무도 처리하지 않는다. 이 태스크를 Celery beat 로 주기 실행해 회수한다.
    """

    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    requeued = 0
    with session_scope() as session:
        stale = list(
            session.scalars(
                select(models.Scan).where(
                    models.Scan.status == "queued",
                    models.Scan.created_at < cutoff,
                )
            )
        )
        for scan in stale:
            if scan.source_path.startswith("git:"):
                log.warning(
                    "orphan git scan %s — 수동 재큐잉 필요 (원본 URL 필요)", scan.id
                )
                continue
            run_scan_task.delay(scan.id, scan.source_path)
            requeued += 1
    if requeued:
        log.warning("orphan scans requeued: %d", requeued)
    return {"requeued": requeued}


def _contained(candidate: Path, root: Path) -> bool:
    try:
        return candidate == root or candidate.is_relative_to(root)
    except (ValueError, OSError):
        return False
