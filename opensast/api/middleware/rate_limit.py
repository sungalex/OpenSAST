"""IP 기반 rate limit 미들웨어.

slowapi 가 설치되어 있으면 사용하고, 없거나 `rate_limit_per_minute=0` 이면
no-op 으로 조용히 넘긴다. 이렇게 하면 의존성 부재에도 테스트가 깨지지 않고,
local 프로파일에서도 원할 때만 활성된다.
"""

from __future__ import annotations

from fastapi import FastAPI

from opensast.config import Settings
from opensast.utils.logging import get_logger

log = get_logger(__name__)


def install_rate_limit(app: FastAPI, settings: Settings) -> None:
    if settings.rate_limit_per_minute <= 0:
        return
    try:
        from slowapi import Limiter
        from slowapi.errors import RateLimitExceeded
        from slowapi.middleware import SlowAPIMiddleware
        from slowapi.util import get_remote_address
    except ImportError:
        log.info("slowapi not installed — rate limiting disabled")
        return

    # Redis 사용 가능하면 분산 rate limit
    storage_uri = None
    if settings.redis_url:
        storage_uri = settings.redis_url
        log.info("rate limit: using Redis backend (%s)", settings.redis_url)

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[f"{settings.rate_limit_per_minute}/minute"],
        storage_uri=storage_uri,
    )
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request, exc):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            {"detail": "요청 한도를 초과했습니다. 잠시 후 다시 시도하세요."},
            status_code=429,
        )

    app.add_middleware(SlowAPIMiddleware)
    log.info(
        "rate limit enabled: %d/min per IP", settings.rate_limit_per_minute
    )
