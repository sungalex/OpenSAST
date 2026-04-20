"""FastAPI 애플리케이션 팩토리.

프로파일(`local`/`docker`/`cloud`)에 따라 CORS, 보안 헤더, rate limit, 문서 노출
등의 동작이 자동 조정된다. 플러그인 레지스트리도 startup 시 entry_points 를
발견하여 내장 + 외부 플러그인 모두 활성화된다.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from opensast.api.middleware import install as install_middleware
from opensast.api.middleware.prometheus import metrics_response
from opensast.api.routes import (
    audit,
    auth,
    dashboard,
    findings,
    gate,
    mois,
    organizations,
    projects,
    reports,
    rule_sets,
    scans,
    suppressions,
)
from opensast.config import Settings, get_settings
from opensast.db import repo
from opensast.db.migrate import auto_migrate
from opensast.db.session import init_engine, session_scope
from opensast.observability import init_telemetry
from opensast.plugins.registry import discover_all
from opensast.utils.logging import get_logger

log = get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    # 프로파일 무결성 검사 — 운영 환경에서 약한 시크릿 등 경고
    for warning in settings.validate_profile():
        log.warning(warning)

    # 내부 import 가 opensast.engines / opensast.llm 을 건드려 내장 플러그인이
    # 레지스트리에 등록되도록 한다.
    import opensast.engines  # noqa: F401
    import opensast.llm  # noqa: F401

    app = FastAPI(
        title=settings.app_name,
        version="0.5.0",
        description="행안부 49개 구현단계 보안약점 진단 API",
        docs_url=None,   # 기본 docs 비활성 → 커스텀으로 대체
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )

    # Swagger UI 정적 파일 — CDN 의존 제거 (폐쇄망 지원)
    static_dir = Path(settings.project_root) / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    if settings.enable_docs:
        from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

        @app.get("/docs", include_in_schema=False)
        async def swagger_ui():
            return get_swagger_ui_html(
                openapi_url="/openapi.json",
                title=f"{settings.app_name} - Swagger UI",
                swagger_js_url="/static/swagger-ui-bundle.js",
                swagger_css_url="/static/swagger-ui.css",
            )

        @app.get("/redoc", include_in_schema=False)
        async def redoc():
            return get_redoc_html(
                openapi_url="/openapi.json",
                title=f"{settings.app_name} - ReDoc",
            )

    install_middleware(app, settings)

    @app.on_event("startup")
    def _startup() -> None:
        init_telemetry()
        engine = init_engine(settings)
        auto_migrate(engine)
        discover_all()  # 외부 entry_points 플러그인 탐색
        with session_scope() as session:
            repo.ensure_bootstrap_admin(session, settings=settings)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "app": settings.app_name, "profile": settings.profile.value}

    @app.get("/ready", tags=["system"])
    def ready() -> dict:
        """Readiness probe — DB + Redis + Celery broker 연결 테스트."""

        from sqlalchemy import text

        checks: dict[str, str] = {}

        # DB check
        try:
            with session_scope() as session:
                session.execute(text("SELECT 1"))
            checks["db"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["db"] = str(exc)

        # Redis check
        try:
            import redis
            r = redis.from_url(settings.redis_url)
            r.ping()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = str(exc)

        # Celery broker check
        try:
            from opensast.worker import celery_app
            conn = celery_app.connection()
            conn.ensure_connection(max_retries=1, timeout=2)
            conn.close()
            checks["celery"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["celery"] = str(exc)

        all_ok = all(v == "ok" for v in checks.values())
        if not all_ok:
            log.warning("readiness check degraded: %s", checks)
        return {"status": "ready" if all_ok else "degraded", "checks": checks}

    @app.get("/metrics", tags=["system"])
    def metrics():
        """Prometheus scrape 엔드포인트."""
        return metrics_response()

    app.include_router(auth.router)
    app.include_router(organizations.router)
    app.include_router(projects.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(mois.router)
    app.include_router(dashboard.router)
    app.include_router(rule_sets.router)
    app.include_router(suppressions.router)
    app.include_router(gate.router)
    app.include_router(audit.router)
    return app


app = create_app()
