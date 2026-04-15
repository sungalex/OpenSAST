"""로그인 실패 누적 후 계정 잠금 E2E."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_account_locks_after_threshold(client: TestClient) -> None:
    """기본 settings.failed_login_threshold=5 기준."""

    # 5회 실패
    for _ in range(5):
        r = client.post(
            "/api/auth/login",
            json={"email": "admin@aisast.local", "password": "wrong"},
        )
        assert r.status_code == 401

    # 6번째: 이미 잠금 → 올바른 비밀번호로도 423 반환
    r = client.post(
        "/api/auth/login",
        json={"email": "admin@aisast.local", "password": "aisast-admin"},
    )
    assert r.status_code == 423
    assert "잠겨" in r.json()["detail"]
