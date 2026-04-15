"""요청 본문 크기 제한.

Content-Length 헤더가 명시된 경우 사전에 413 을 반환해 조기 차단한다. 업로드
엔드포인트는 별도 상한을 적용해 일반 API 는 더 엄격하게 유지할 수 있다.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RequestSizeMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        default_max_bytes: int,
        upload_max_bytes: int,
        upload_path_prefixes: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self.default_max_bytes = default_max_bytes
        self.upload_max_bytes = upload_max_bytes
        self.upload_path_prefixes = upload_path_prefixes

    def _limit_for(self, path: str) -> int:
        for prefix in self.upload_path_prefixes:
            if path.startswith(prefix):
                return self.upload_max_bytes
        return self.default_max_bytes

    async def dispatch(self, request: Request, call_next):
        limit = self._limit_for(request.url.path)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
            except ValueError:
                return JSONResponse(
                    {"detail": "invalid Content-Length"}, status_code=400
                )
            if size > limit:
                return JSONResponse(
                    {
                        "detail": f"request body too large: {size} > {limit}",
                    },
                    status_code=413,
                )
        return await call_next(request)
