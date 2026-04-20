"""OpenTelemetry 초기화 — 환경변수로 on/off 제어.

활성화: OTEL_EXPORTER_OTLP_ENDPOINT 환경변수가 설정되면 자동 활성화.
비활성: 기본값 (환경변수 미설정 또는 OPENSAST_OTEL_ENABLED=false).
"""

from __future__ import annotations

import os

from opensast.utils.logging import get_logger

log = get_logger(__name__)


def init_telemetry(service_name: str = "aisast") -> None:
    """OpenTelemetry TracerProvider + 계측기를 초기화한다."""

    enabled = os.environ.get("OPENSAST_OTEL_ENABLED", "").lower() in ("1", "true", "yes")
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not enabled and not endpoint:
        log.debug("OpenTelemetry disabled (set OPENSAST_OTEL_ENABLED=true or OTEL_EXPORTER_OTLP_ENDPOINT)")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        if endpoint:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        # FastAPI 계측
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument()
        except ImportError:
            pass

        # SQLAlchemy 계측
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument()
        except ImportError:
            pass

        # Celery 계측
        try:
            from opentelemetry.instrumentation.celery import CeleryInstrumentor
            CeleryInstrumentor().instrument()
        except ImportError:
            pass

        log.info("OpenTelemetry initialized (endpoint=%s)", endpoint or "default")
    except ImportError:
        log.info("OpenTelemetry SDK not installed — tracing disabled")
    except Exception as exc:
        log.warning("OpenTelemetry init failed: %s", exc)
