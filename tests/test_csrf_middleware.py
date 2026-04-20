"""v0.5.0 CSRF 미들웨어 테스트."""

from opensast.api.middleware.csrf import CSRFMiddleware


class TestCSRFMiddleware:
    def test_get_passes_without_token(self, client):
        """GET 요청은 CSRF 토큰 없이도 통과."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_csrf_cookie_name(self):
        """CSRF 쿠키/헤더 이름 상수 확인."""
        from opensast.api.middleware.csrf import _COOKIE_NAME, _HEADER_NAME

        assert _COOKIE_NAME == "aisast_csrf"
        assert _HEADER_NAME == "x-csrf-token"

    def test_exempt_paths(self):
        """로그인, refresh, 시스템 경로 면제."""
        from opensast.api.middleware.csrf import _EXEMPT_PATHS

        assert "/api/auth/login" in _EXEMPT_PATHS
        assert "/api/auth/refresh" in _EXEMPT_PATHS
        assert "/health" in _EXEMPT_PATHS
