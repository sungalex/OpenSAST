"""v0.5.0 인증 강화 테스트 — JWT iat/jti, refresh token."""

from opensast.api.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
)


class TestJWTEnhancements:
    def test_access_token_has_iat_jti(self):
        token = create_access_token("test@example.com", "admin")
        payload = decode_access_token(token)
        assert payload is not None
        assert "iat" in payload
        assert "jti" in payload
        assert payload["type"] == "access"
        assert payload["sub"] == "test@example.com"
        assert payload["role"] == "admin"

    def test_refresh_token_has_type(self):
        token = create_refresh_token("test@example.com")
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"
        assert "jti" in payload

    def test_jti_is_unique(self):
        t1 = create_access_token("a@b.com", "admin")
        t2 = create_access_token("a@b.com", "admin")
        p1 = decode_access_token(t1)
        p2 = decode_access_token(t2)
        assert p1["jti"] != p2["jti"]


class TestRefreshEndpoint:
    def test_refresh_returns_new_tokens_via_header(self, client, admin_token):
        """Authorization 헤더 폴백으로 refresh token 제출."""
        from opensast.api.security import create_refresh_token

        refresh = create_refresh_token("admin@opensast.local")
        resp = client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {refresh}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

    def test_refresh_rejects_access_token(self, client, admin_token):
        """access token으로 refresh 시도 시 거부."""
        # TestClient가 이전 login의 cookie를 가지고 있을 수 있으므로 cookie 제거
        client.cookies.clear()
        resp = client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 401

    def test_login_sets_refresh_cookie(self, client):
        """로그인 시 refresh token이 HttpOnly 쿠키로 설정."""
        resp = client.post(
            "/api/auth/login",
            json={"email": "admin@opensast.local", "password": "opensast-admin"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        # refresh token은 Set-Cookie로 전달
        cookies = resp.cookies
        assert "aisast_refresh" in cookies or any(
            "aisast_refresh" in h for h in resp.headers.get_list("set-cookie")
        )

    def test_logout_clears_refresh_cookie(self, client, admin_token):
        """로그아웃 시 refresh 쿠키 삭제."""
        resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["detail"] == "logged out"
