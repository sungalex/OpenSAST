"""CSRF 방어 — Double-Submit Cookie 패턴.

SPA 아키텍처에서 state-changing 요청(POST/PUT/PATCH/DELETE)에 대해
쿠키의 csrf 토큰과 헤더의 X-CSRF-Token 값이 일치하는지 검증한다.
GET/HEAD/OPTIONS 및 /api/auth/login 은 면제.
"""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/refresh", "/health", "/ready", "/metrics"}
_COOKIE_NAME = "aisast_csrf"
_HEADER_NAME = "x-csrf-token"


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # 안전한 메서드 또는 면제 경로 → 통과
        if request.method in _SAFE_METHODS or request.url.path in _EXEMPT_PATHS:
            response = await call_next(request)
            # GET 응답에 CSRF 쿠키 발급 (없으면)
            if _COOKIE_NAME not in request.cookies:
                token = secrets.token_hex(32)
                response.set_cookie(
                    _COOKIE_NAME,
                    token,
                    httponly=False,  # JS에서 읽어야 함
                    samesite="strict",
                    secure=request.url.scheme == "https",
                    max_age=86400,
                )
            return response

        # state-changing 요청 → 토큰 검증
        cookie_token = request.cookies.get(_COOKIE_NAME)
        header_token = request.headers.get(_HEADER_NAME)

        if not cookie_token or not header_token or cookie_token != header_token:
            return JSONResponse(
                {"detail": "CSRF 토큰이 누락되었거나 일치하지 않습니다."},
                status_code=403,
            )

        response = await call_next(request)
        return response
