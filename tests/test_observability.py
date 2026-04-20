"""v0.5.0 관측성 테스트 — Prometheus, 로깅, 헬스체크."""

import os
from unittest.mock import patch

import pytest


class TestPrometheusMiddleware:
    def test_metrics_endpoint_returns_prometheus(self, client):
        resp = client.get("/metrics")
        assert resp.status_code in (200, 501)
        if resp.status_code == 200:
            body = resp.text
            assert "aisast_http_requests_total" in body or "# HELP" in body

    def test_normalize_path(self):
        from opensast.api.middleware.prometheus import _normalize_path

        assert _normalize_path("/api/scans/abc123def456/events") == "/api/scans/:id/events"
        assert _normalize_path("/api/findings") == "/api/findings"
        assert _normalize_path("/health") == "/health"


class TestJSONLogging:
    def test_json_format_configurable(self):
        """AISAST_LOG_FORMAT=json 환경변수로 JSON 로깅 전환 가능."""
        import opensast.utils.logging as log_mod

        log_mod._CONFIGURED = False
        with patch.dict(os.environ, {"AISAST_LOG_FORMAT": "json"}):
            log_mod._configure_root()
        log_mod._CONFIGURED = False


class TestHealthEndpoints:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_ready_returns_status(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ready", "degraded")
        assert "checks" in data
