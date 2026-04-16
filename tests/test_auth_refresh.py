"""v0.5.0 인증 강화 테스트 — JWT iat/jti, refresh token."""

from aisast.api.security import (
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
    def test_refresh_returns_new_tokens(self, client, admin_token):
        from aisast.api.security import create_refresh_token

        refresh = create_refresh_token("admin@aisast.local")
        resp = client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {refresh}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_refresh_rejects_access_token(self, client, admin_token):
        resp = client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 401

    def test_login_returns_refresh_token(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "admin@aisast.local", "password": "aisast-admin"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "refresh_token" in data
        assert data["refresh_token"] is not None
