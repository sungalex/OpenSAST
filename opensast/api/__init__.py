"""FastAPI 기반 API Gateway.

`app` 은 지연 생성된다 — 이 패키지를 import 하는 것만으로 애플리케이션이
만들어지지 않는다. ASGI 서버는 `opensast.api.app:app` 을 그대로 쓰면 된다.
"""

from opensast.api.app import create_app, get_app

__all__ = ["create_app", "get_app"]
