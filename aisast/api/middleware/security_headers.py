"""HTTP 응답 보안 헤더.

OWASP Secure Headers 권고를 기반으로 다음 헤더를 응답에 자동 부착한다:

- `Strict-Transport-Security` (enforce_https=True 일 때)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `Content-Security-Policy`: nonce 기반 CSP (unsafe-inline 제거)
"""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, enforce_https: bool = False) -> None:
        super().__init__(app)
        self.enforce_https = enforce_https

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        nonce = secrets.token_urlsafe(16)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"img-src 'self' data: https:; "
            f"connect-src 'self' http://localhost:* https:; "
            f"font-src 'self' data:; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self';",
        )
        if self.enforce_https:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
