"""FastAPI 애플리케이션 팩토리.

프로파일(`local`/`docker`/`cloud`)에 따라 CORS, 보안 헤더, rate limit, 문서 노출
등의 동작이 자동 조정된다. 플러그인 레지스트리도 startup 시 entry_points 를
발견하여 내장 + 외부 플러그인 모두 활성화된다.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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
from opensast.services.base import ServiceError
from opensast.utils.logging import get_logger

log = get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    # 프로파일 무결성 검사.
    # cloud 프로파일에서는 경고가 곧 기동 실패다 (ADR-002) — 약한 시크릿이나
    # 빈/와일드카드 CORS 로 운영에 올라가는 경로를 막는다.
    for warning in settings.enforce_startup_policy():
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

    @app.exception_handler(ServiceError)
    async def _service_error_handler(_request: Request, exc: ServiceError):
        """서비스 계층 도메인 오류를 HTTP 응답으로 변환한다.

        라우트마다 try/except 를 반복하면 한 곳만 빠뜨려도 500 이 새어 나간다
        (실제로 조직 스코핑 404 가 500 으로 노출된 적이 있다). 변환은 한 곳에서만
        한다.
        """

        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )


    @app.on_event("startup")
    def _startup() -> None:
        init_telemetry()
        engine = init_engine(settings)
        if settings.auto_migrate_on_startup:
            auto_migrate(engine)
        else:
            log.info(
                "auto_migrate 비활성 (profile=%s) — 스키마는 "
                "`alembic upgrade head` 로만 변경합니다",
                settings.profile.value,
            )
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
            from opensast.orchestrator.celery_app import celery_app

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


# ---------------------------------------------------------------------------
# ASGI 엔트리포인트 — **지연 생성** (PEP 562)
# ---------------------------------------------------------------------------
#
# 예전에는 모듈 최상단에서 `app = create_app()` 을 실행했다. 그러면
# `from opensast.api.security import ...` 처럼 하위 모듈 하나만 가져와도
# (`opensast/api/__init__.py` 가 이 모듈을 import 하므로) 앱 전체가 생성된다 —
# 설정 검증, DB 엔진, 플러그인 탐색까지 전부.
#
# 실제로 cloud 프로파일에서는 설정 검증이 기동 실패를 던지므로, 토큰 헬퍼를
# import 하려는 것만으로 예외가 났고 테스트 수집 단계가 통째로 중단됐다.
#
# `__getattr__` 로 미루면 `uvicorn opensast.api.app:app` 은 그대로 동작하면서
# (속성 접근 시 생성), 단순 import 는 부작용을 일으키지 않는다.

_app: FastAPI | None = None


def get_app() -> FastAPI:
    """ASGI 애플리케이션을 (필요하면 생성해서) 반환한다."""

    global _app
    if _app is None:
        _app = create_app()
    return _app


def __getattr__(name: str) -> FastAPI:
    if name == "app":
        return get_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
