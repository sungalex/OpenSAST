"""Celery 태스크 정의.

웹 API는 스캔 작업을 큐잉하고, 워커가 `run_scan_task` / `clone_and_scan_task`
를 수행한다. 결과는 PostgreSQL에 저장되며, 비동기 상태는 Celery 자체의
backend로 추적한다.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy import select

from aisast.config import get_settings
from aisast.db import models, repo
from aisast.db.session import session_scope
from aisast.orchestrator.celery_app import celery_app
from aisast.orchestrator.pipeline import ScanOptions, run_scan
from aisast.utils.logging import get_logger
from aisast.utils.paths import ensure_dir
from aisast.utils.subprocess import run_capture

log = get_logger(__name__)


@celery_app.task(
    name="aisast.run_scan",
    bind=True,
    autoretry_for=(Exception,),
    max_retries=2,
    retry_backoff=True,
    retry_backoff_max=120,
    acks_late=True,
)
def run_scan_task(
    self,
    scan_id: str,
    source_path: str,
    enable_second_pass: bool = True,
    enable_triage: bool = True,
    language_hint: str | None = None,
) -> dict:
    """큐잉된 스캔을 실제 실행한다."""

    root = Path(source_path)
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
    except Exception as exc:
        log.exception("scan %s failed: %s", scan_id, exc)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error=str(exc))
        raise

    self.update_state(state="PROGRESS", meta={"phase": "persisting", "progress": 90})

    with session_scope() as session:
        repo.persist_scan_result(session, scan_id, result)
    return {
        "scan_id": scan_id,
        "total_findings": len(result.findings),
        "engine_stats": result.engine_stats,
    }


@celery_app.task(
    name="aisast.clone_and_scan",
    bind=True,
    autoretry_for=(Exception,),
    max_retries=2,
    retry_backoff=True,
    retry_backoff_max=120,
    acks_late=True,
)
def clone_and_scan_task(
    self,
    scan_id: str,
    git_url: str,
    branch: str | None = None,
    enable_second_pass: bool = True,
    enable_triage: bool = True,
    language_hint: str | None = None,
) -> dict:
    """Git URL 을 임시 디렉터리에 clone 후 스캔한다.

    clone 이 성공하면 `run_scan_task` 와 동일한 파이프라인으로 결과를 저장한다.
    `settings.work_dir/sources/<scan_id>` 에 작업 디렉터리가 생성되며 스캔이
    완료되면 해당 디렉터리를 삭제한다.
    """

    settings = get_settings()
    scan_root = Path(settings.work_dir) / "sources" / scan_id
    ensure_dir(scan_root.parent)

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [git_url, str(scan_root)]

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
            shutil.rmtree(scan_root, ignore_errors=True)
            return {"scan_id": scan_id, "status": "failed"}

        options = ScanOptions(
            enable_second_pass=enable_second_pass,
            enable_triage=enable_triage,
            language_hint=language_hint,
        )
        result = run_scan(scan_root, options=options)
    except Exception as exc:
        log.exception("clone_and_scan %s crashed: %s", scan_id, exc)
        with session_scope() as session:
            repo.mark_scan_failed(session, scan_id, error=str(exc))
        shutil.rmtree(scan_root, ignore_errors=True)
        raise

    # source_path 를 실제 체크아웃 경로로 업데이트
    with session_scope() as session:
        scan_row = session.get(models.Scan, scan_id)
        if scan_row is not None:
            scan_row.source_path = str(scan_root)
        repo.persist_scan_result(session, scan_id, result)

    # 스캔 완료 후 디스크 정리 (리포트/Finding 은 DB 에 있으므로 안전)
    shutil.rmtree(scan_root, ignore_errors=True)

    return {
        "scan_id": scan_id,
        "total_findings": len(result.findings),
        "engine_stats": result.engine_stats,
    }


@celery_app.task(
    name="aisast.triage_batch",
    bind=True,
    autoretry_for=(Exception,),
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
    from aisast.llm.triage import Triager
    from aisast.models import CodeLocation, Finding as DomainFinding
    from aisast.mois.catalog import Severity

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

        # DB -> 도메인 변환
        domain_findings = []
        for r in rows:
            domain_findings.append(DomainFinding(
                rule_id=r.rule_id,
                engine=r.engine,
                message=r.message,
                severity=Severity(r.severity),
                location=CodeLocation(
                    file_path=r.file_path,
                    start_line=r.start_line,
                    end_line=r.end_line,
                    snippet=r.snippet,
                ),
                cwe_ids=tuple(r.cwe_ids or []),
                mois_id=r.mois_id,
                language=r.language,
            ))

        triager = Triager()
        triager.triage(domain_findings)

        # 결과 반영
        for dom, row in zip(domain_findings, rows):
            if dom.triage is not None:
                if row.triage is None:
                    row.triage = models.TriageRecord(
                        finding_id=row.id,
                        verdict=dom.triage.verdict,
                        fp_probability=dom.triage.fp_probability,
                        rationale=dom.triage.rationale,
                        recommended_fix=dom.triage.recommended_fix,
                        patched_code=dom.triage.patched_code,
                        model=dom.triage.model,
                    )
                else:
                    row.triage.verdict = dom.triage.verdict
                    row.triage.fp_probability = dom.triage.fp_probability
                    row.triage.rationale = dom.triage.rationale
                    row.triage.model = dom.triage.model

    return {"scan_id": scan_id, "triaged": len(domain_findings)}
