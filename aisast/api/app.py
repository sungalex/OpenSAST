"""FastAPI 애플리케이션 팩토리."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aisast.api.routes import (
    audit,
    auth,
    dashboard,
    findings,
    gate,
    mois,
    projects,
    reports,
    rule_sets,
    scans,
    suppressions,
)
from aisast.config import get_settings
from aisast.db import repo
from aisast.db.base import Base
from aisast.db.migrate import auto_migrate
from aisast.db.session import init_engine, session_scope


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="행안부 49개 구현단계 보안약점 진단 API",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def _startup() -> None:
        engine = init_engine(settings)
        auto_migrate(engine)
        with session_scope() as session:
            repo.ensure_bootstrap_admin(session, settings=settings)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "app": settings.app_name}

    app.include_router(auth.router)
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
