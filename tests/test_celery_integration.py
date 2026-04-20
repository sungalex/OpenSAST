"""Celery eager 모드 통합 테스트.

실제 브로커 없이 task_always_eager=True로 동기 실행.
"""
import pytest
from pathlib import Path


@pytest.fixture
def celery_eager(monkeypatch):
    from aisast.orchestrator.celery_app import celery_app
    celery_app.conf.update(task_always_eager=True, task_eager_propagates=True)
    yield celery_app
    celery_app.conf.update(task_always_eager=False, task_eager_propagates=False)


class TestCeleryEager:
    def test_celery_app_config(self):
        from aisast.orchestrator.celery_app import celery_app
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.task_track_started is True

    def test_task_annotations_exist(self):
        from aisast.orchestrator.celery_app import celery_app
        annotations = celery_app.conf.task_annotations or {}
        assert "aisast.run_scan" in annotations
        assert "aisast.triage_batch" in annotations
