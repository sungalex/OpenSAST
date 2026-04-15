"""인증 라우트 통합 테스트."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_login_success(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login",
        json={"email": "admin@aisast.local", "password": "aisast-admin"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"
    assert len(body["access_token"]) > 50  # JWT


def test_login_local_tld_allowed(client: TestClient) -> None:
    """.local TLD 가 EmailStr 검증 회귀로 깨지지 않는지 확인."""

    r = client.post(
        "/api/auth/login",
        json={"email": "admin@aisast.local", "password": "aisast-admin"},
    )
    assert r.status_code == 200


def test_login_wrong_password_returns_401(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login",
        json={"email": "admin@aisast.local", "password": "WRONG"},
    )
    assert r.status_code == 401


def test_login_invalid_email_format_returns_422(client: TestClient) -> None:
    r = client.post(
        "/api/auth/login", json={"email": "no-at-sign", "password": "anything"}
    )
    assert r.status_code == 422


def test_create_user_requires_admin(
    client: TestClient, analyst_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/auth/users",
        headers=analyst_headers,
        json={
            "email": "another@aisast.local",
            "password": "long-enough-pw",
            "role": "analyst",
        },
    )
    assert r.status_code == 403


def test_create_user_admin_succeeds(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "email": "third@example.com",
            # 정책: 12자 이상, upper+lower+digit+special 중 3종 이상
            "password": "Compliant#Pass1",
            "display_name": "Third",
            "role": "viewer",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email"] == "third@example.com"
    assert body["role"] == "viewer"
    assert body["is_active"] is True


def test_create_user_rejects_weak_password(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    r = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "email": "weak@example.com",
            "password": "password1234",  # 흔한 비밀번호 + 문자 종류 부족
            "role": "viewer",
        },
    )
    assert r.status_code == 422


def test_protected_route_without_token_returns_401(client: TestClient) -> None:
    r = client.get("/api/projects")
    assert r.status_code == 401
