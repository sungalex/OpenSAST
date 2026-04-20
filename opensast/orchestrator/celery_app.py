"""Celery 애플리케이션 초기화.

Celery 의 worker pool 은 플랫폼 의존성이 있어 자동 선택 로직을 포함한다:

- **Linux / macOS** → `prefork` (기본, fork 기반)
- **Windows 네이티브** → `solo` (Celery 4+ 에서 Windows prefork 미지원)
- **기타 POSIX** → `prefork`

사용자는 `OPENSAST_CELERY_POOL` 환경변수(`prefork|solo|gevent|eventlet|threads`)로
강제 오버라이드할 수 있다.

이 함수는 `recommended_pool()` 로 추천값을 계산하며, 실제 워커 실행 시
`celery -A opensast.orchestrator.celery_app worker --pool=<pool>` 로 전달한다.
"""

from __future__ import annotations

import os
import sys

from celery import Celery

from opensast.config import get_settings
from opensast.utils.logging import get_logger

log = get_logger(__name__)


def recommended_pool() -> str:
    """플랫폼에 맞는 Celery worker pool 이름 반환.

    우선순위:
      1. `OPENSAST_CELERY_POOL` 환경변수
      2. Windows → "solo"
      3. 그 외 → "prefork"
    """

    override = os.environ.get("OPENSAST_CELERY_POOL")
    if override:
        return override.strip().lower()
    if sys.platform.startswith("win"):
        return "solo"
    return "prefork"


def create_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "aisast",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=["opensast.orchestrator.tasks"],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="Asia/Seoul",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=7200,
        task_soft_time_limit=3600,
        worker_prefetch_multiplier=1,
        # 플랫폼에 맞는 pool 힌트 — worker 실행 시 명시하지 않으면 사용됨
        worker_pool=recommended_pool(),
        task_annotations={
            "opensast.run_scan": {
                "soft_time_limit": settings.scan_task_soft_time_limit,
                "time_limit": settings.scan_task_time_limit,
            },
            "opensast.clone_and_scan": {
                "soft_time_limit": settings.scan_task_soft_time_limit,
                "time_limit": settings.scan_task_time_limit,
            },
            "opensast.triage_batch": {
                "soft_time_limit": settings.triage_task_soft_time_limit,
                "time_limit": settings.triage_task_time_limit,
            },
        },
    )
    log.info("celery app initialized (pool=%s)", recommended_pool())
    return app


celery_app = create_celery_app()
