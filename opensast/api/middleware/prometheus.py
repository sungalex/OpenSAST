"""Prometheus 메트릭 미들웨어 + /metrics 엔드포인트."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    from prometheus_client import (
        Counter,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    REQUEST_COUNT = Counter(
        "opensast_http_requests_total",
        "Total HTTP requests",
        ["method", "path_template", "status"],
    )
    REQUEST_LATENCY = Histogram(
        "opensast_http_request_duration_seconds",
        "HTTP request latency",
        ["method", "path_template"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
    SCAN_FINDINGS = Counter(
        "opensast_scan_findings_total",
        "Total findings produced by scans",
        ["engine", "severity"],
    )
    TRIAGE_DURATION = Histogram(
        "aisast_triage_duration_seconds",
        "LLM triage call duration",
        ["provider"],
    )
    _ENABLED = True
except ImportError:
    _ENABLED = False


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if not _ENABLED:
            return await call_next(request)
        method = request.method
        path = request.url.path
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        # 경로 템플릿 정규화 (scan ID 등 동적 부분 제거)
        path_tmpl = _normalize_path(path)
        REQUEST_COUNT.labels(method=method, path_template=path_tmpl, status=response.status_code).inc()
        REQUEST_LATENCY.labels(method=method, path_template=path_tmpl).observe(elapsed)
        return response


def _normalize_path(path: str) -> str:
    """동적 경로 세그먼트를 :id 로 치환."""
    parts = path.rstrip("/").split("/")
    normalized = []
    for i, part in enumerate(parts):
        if i > 0 and parts[i - 1] in ("scans", "findings", "projects", "users") and part.isalnum() and len(part) > 3:
            normalized.append(":id")
        else:
            normalized.append(part)
    return "/".join(normalized) or "/"


def metrics_response() -> Response:
    """Prometheus scrape 엔드포인트 응답 생성."""
    if not _ENABLED:
        return Response("prometheus-client not installed", status_code=501)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
