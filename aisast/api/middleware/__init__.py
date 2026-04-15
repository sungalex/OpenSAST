"""FastAPI 미들웨어 패키지 — 보안 헤더, rate limit, 요청 크기 제한, CORS.

`install(app, settings)` 를 호출하면 설정 프로파일에 맞춰 필요한 미들웨어를
모두 적용한다. 개별 미들웨어는 프로파일 기본값 + 환경변수 재정의를 존중한다.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aisast.config import Settings
from aisast.api.middleware.rate_limit import install_rate_limit
from aisast.api.middleware.request_size import RequestSizeMiddleware
from aisast.api.middleware.security_headers import SecurityHeadersMiddleware


def install(app: FastAPI, settings: Settings) -> None:
    """프로파일에 맞는 보안 미들웨어 일괄 설치.

    순서가 중요하다:
      1. Rate limit (outermost — 빠른 거부)
      2. Request size
      3. CORS
      4. Security headers (innermost — 응답 직전에 부착)
    """

    # CORS — allowlist 기반
    origins = settings.cors_origins or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-Id"],
    )

    # Security headers
    if settings.security_headers_enabled:
        app.add_middleware(
            SecurityHeadersMiddleware,
            enforce_https=settings.enforce_https,
        )

    # Request size limit
    app.add_middleware(
        RequestSizeMiddleware,
        default_max_bytes=settings.max_body_bytes,
        upload_max_bytes=settings.max_upload_bytes,
        upload_path_prefixes=("/api/scans/upload",),
    )

    # Rate limit (slowapi) — 가장 바깥
    install_rate_limit(app, settings)


__all__ = [
    "install",
    "RequestSizeMiddleware",
    "SecurityHeadersMiddleware",
    "install_rate_limit",
]
