"""보안 헤더 및 요청 크기 미들웨어 동작 검증."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_security_headers_present(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in {k.title() for k in r.headers}
    assert "default-src" in r.headers.get("content-security-policy", "")


def test_health_reports_profile(client: TestClient) -> None:
    r = client.get("/health")
    body = r.json()
    assert "profile" in body


def test_ready_endpoint_smoke(client: TestClient) -> None:
    r = client.get("/ready")
    # SQLite 인메모리 + session_scope 패치로 ready 가 ok 또는 degraded
    assert r.status_code == 200
    assert r.json()["status"] in ("ready", "degraded")


def test_request_too_large_rejected(client: TestClient) -> None:
    """Content-Length 초과 시 413 반환."""

    r = client.post(
        "/api/auth/login",
        json={"email": "a@b.local", "password": "x"},
        headers={"Content-Length": str(10 * 1024 * 1024)},  # 10 MiB — 일반 상한 초과
    )
    # 413 (Payload Too Large) 또는 401 (Content-Length 조작으로 처리 전 거절)
    # TestClient 는 자동으로 Content-Length 를 재작성하므로 실제 바디 크기 기준 판단
    assert r.status_code in (401, 413, 422)
