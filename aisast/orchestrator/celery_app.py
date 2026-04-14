"""Celery 애플리케이션 초기화.

Celery는 선택적 의존성으로 취급하며, 본 모듈은 API 서버 및 워커 양쪽이
공유한다. 설정은 `aisast.config.Settings`에서 읽어온다.
"""

from __future__ import annotations

from celery import Celery

from aisast.config import get_settings


def create_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "aisast",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=["aisast.orchestrator.tasks"],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="Asia/Seoul",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=3600,
        worker_prefetch_multiplier=1,
    )
    return app


celery_app = create_celery_app()
