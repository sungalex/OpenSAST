"""공용 pytest 픽스처.

모든 통합 테스트는 SQLite 인메모리 DB 로 격리되어 실행되며 Celery 의 .delay 호출은
no-op 으로 모킹된다. 각 테스트마다 새로운 엔진과 세션을 만들고, FastAPI
TestClient 는 의존성 주입을 통해 동일한 세션을 공유한다.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from tests._credentials import ANALYST_PASSWORD, VIEWER_PASSWORD


@pytest.fixture(autouse=True)
def isolate_from_dotenv(monkeypatch):
    """테스트를 리포지토리 `.env` 로부터 격리한다.

    `Settings` 는 `SettingsConfigDict(env_file=".env")` 로 선언돼 있어, 개발자가
    로컬에 둔 `.env` 값이 테스트 결과를 바꾼다. 실제로 `.env` 에
    `OPENSAST_LLM_PROVIDER` 가 있으면 오버레이 테스트가 실패했다 — 제품 동작은
    정상(환경변수가 오버레이보다 우선)인데 테스트만 환경에 의존한 것이다.

    테스트는 개발자 머신 상태와 무관하게 같은 결과를 내야 하므로 여기서 끊는다.
    `.env` 자체의 로딩을 검증하려면 이 픽스처를 명시적으로 되돌리고 쓴다.
    """

    from opensast.config import Settings, reset_settings_cache

    monkeypatch.setitem(Settings.model_config, "env_file", None)
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def mock_redis_blacklist(monkeypatch):
    """테스트에서 Redis 블랙리스트 호출을 차단."""
    monkeypatch.setattr("opensast.api.security.is_blacklisted", lambda jti: False)
    monkeypatch.setattr("opensast.api.security.blacklist_token", lambda jti, ttl_seconds=None: None)
    monkeypatch.setattr("opensast.api.security.is_refresh_consumed", lambda jti: False)
    monkeypatch.setattr("opensast.api.security.mark_refresh_consumed", lambda jti, ttl_seconds=7*86400: None)


# ---------------------------------------------------------------------------
# DB / app 픽스처
# ---------------------------------------------------------------------------


@pytest.fixture
def db_engine():
    """테스트 격리용 SQLite 인메모리 엔진.

    StaticPool 을 써야 같은 인메모리 DB 가 여러 connection 에서 공유된다.
    """

    from opensast.db.base import Base

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine) -> Iterator[Session]:
    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_engine, monkeypatch) -> Iterator[TestClient]:
    """의존성 오버라이드된 FastAPI TestClient.

    - get_db: 테스트 엔진의 세션을 yield
    - Celery .delay: no-op MagicMock
    - 부트스트랩 admin 자동 시드 (admin@opensast.local / opensast-admin)
    - LLM 클라이언트는 NoopLLMClient 로 강제 (네트워크 요청 차단)
    """

    # Celery .delay 모킹 — 실제 브로커 호출 차단
    from opensast.orchestrator import tasks as task_mod

    monkeypatch.setattr(
        task_mod.run_scan_task, "delay", MagicMock(return_value=None)
    )
    monkeypatch.setattr(
        task_mod.clone_and_scan_task, "delay", MagicMock(return_value=None)
    )
    monkeypatch.setattr(
        task_mod.triage_batch_task, "delay", MagicMock(return_value=None)
    )

    # LLM 강제 noop
    monkeypatch.setenv("OPENSAST_LLM_PROVIDER", "noop")

    # API 모듈 import 후 의존성 오버라이드
    from opensast.api.deps import get_db
    from opensast.db import repo
    from opensast.db.session import session_scope

    # startup 에서 PostgreSQL 연결 시도를 차단 — 테스트 엔진 재사용
    monkeypatch.setattr("opensast.api.app.init_engine", lambda s: db_engine)
    monkeypatch.setattr("opensast.api.app.auto_migrate", lambda e: None)

    from opensast.api.app import create_app

    app = create_app()

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)

    def _override_get_db():
        session = Session_()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db

    # session_scope 도 테스트 엔진을 보도록 패치 (auth login 의 record_audit 등)
    from contextlib import contextmanager

    @contextmanager
    def _scope():
        session = Session_()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr("opensast.api.routes.auth.repo", repo)
    monkeypatch.setattr("opensast.db.session.session_scope", _scope)
    monkeypatch.setattr("opensast.api.app.session_scope", _scope)

    # 부트스트랩 admin 시드
    with _scope() as session:
        repo.ensure_bootstrap_admin(session)

    with TestClient(app) as tc:
        yield tc

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 인증 헬퍼
# ---------------------------------------------------------------------------


def _login(client: TestClient, email: str, password: str) -> str:
    r = client.post(
        "/api/auth/login", json={"email": email, "password": password}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def admin_token(client: TestClient) -> str:
    return _login(client, "admin@opensast.local", "opensast-admin")


@pytest.fixture
def admin_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_user(client: TestClient, admin_headers: dict[str, str]) -> dict:
    """analyst 역할 사용자 생성."""

    r = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "email": "analyst@opensast.local",
            # 정책 준수 값을 실행 시 생성한다 (소스에 비밀번호 리터럴을 두지 않음)
            "password": ANALYST_PASSWORD,
            "display_name": "Tester",
            "role": "analyst",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def analyst_token(client: TestClient, analyst_user: dict) -> str:
    return _login(client, "analyst@opensast.local", ANALYST_PASSWORD)


@pytest.fixture
def analyst_headers(analyst_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_user(client: TestClient, admin_headers: dict[str, str]) -> dict:
    """viewer 역할 사용자 생성 — 조회만 가능해야 한다."""

    r = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "email": "viewer@opensast.local",
            "password": VIEWER_PASSWORD,
            "display_name": "Viewer",
            "role": "viewer",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def viewer_headers(client: TestClient, viewer_user: dict) -> dict[str, str]:
    token = _login(client, "viewer@opensast.local", VIEWER_PASSWORD)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def allowed_scan_root(tmp_path, monkeypatch):
    """`OPENSAST_SCAN_ALLOWED_SOURCE_ROOTS` 를 임시 경로로 지정한다.

    기본 구성에서 경로 스캔은 `work_dir` 하위만 허용되므로, 경로 큐잉을 검증하는
    테스트는 허용 루트를 명시해야 한다.
    """

    from opensast.config import reset_settings_cache

    root = tmp_path / "allowed"
    target = root / "proj"
    target.mkdir(parents=True)
    monkeypatch.setenv("OPENSAST_SCAN_ALLOWED_SOURCE_ROOTS", str(root))
    reset_settings_cache()
    try:
        yield target
    finally:
        monkeypatch.delenv("OPENSAST_SCAN_ALLOWED_SOURCE_ROOTS", raising=False)
        reset_settings_cache()


# ---------------------------------------------------------------------------
# 시드 데이터
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_project(client: TestClient, admin_headers: dict[str, str]) -> dict:
    r = client.post(
        "/api/projects",
        headers=admin_headers,
        json={
            "name": "test-project",
            "description": "pytest fixture",
            "default_language": "python",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def sample_scan_with_findings(
    db_engine, sample_project: dict
) -> dict:
    """DB 에 직접 스캔과 다양한 Finding 4건을 시드한다."""

    from sqlalchemy.orm import sessionmaker

    from opensast.db import models

    Session_ = sessionmaker(bind=db_engine, autoflush=False, future=True)
    session = Session_()
    try:
        scan = models.Scan(
            id="testscan0001",
            project_id=sample_project["id"],
            source_path="/tmp/test-source",
            status="completed",
            started_at=datetime(2026, 4, 15, 10, 0, tzinfo=timezone.utc),
            finished_at=datetime(2026, 4, 15, 10, 5, tzinfo=timezone.utc),
            engine_stats={"opengrep": 3, "bandit": 1},
            mois_coverage={"SR1-1": 2, "SR2-4": 1, "SR1-3": 1},
        )
        session.add(scan)
        session.flush()

        findings_data = [
            {
                "rule_id": "mois-sr1-1-python-sql-fstring",
                "engine": "opengrep",
                "severity": "HIGH",
                "message": "SQL 삽입 — f-string",
                "file_path": "src/db.py",
                "start_line": 42,
                "cwe_ids": ["CWE-89"],
                "mois_id": "SR1-1",
                "category": "입력데이터 검증 및 표현",
            },
            {
                "rule_id": "mois-sr1-1-python-sql-fstring",
                "engine": "opengrep",
                "severity": "HIGH",
                "message": "SQL 삽입 — concat",
                "file_path": "src/db.py",
                "start_line": 88,
                "cwe_ids": ["CWE-89"],
                "mois_id": "SR1-1",
                "category": "입력데이터 검증 및 표현",
            },
            {
                "rule_id": "mois-sr1-3-js-innerhtml",
                "engine": "opengrep",
                "severity": "MEDIUM",
                "message": "XSS via innerHTML",
                "file_path": "src/ui/render.js",
                "start_line": 12,
                "cwe_ids": ["CWE-79"],
                "mois_id": "SR1-3",
                "category": "입력데이터 검증 및 표현",
            },
            {
                "rule_id": "B324",
                "engine": "bandit",
                "severity": "LOW",
                "message": "weak hash md5",
                "file_path": "src/util/hash.py",
                "start_line": 7,
                "cwe_ids": ["CWE-327"],
                "mois_id": "SR2-4",
                "category": "보안기능",
            },
        ]
        for i, fd in enumerate(findings_data):
            row = models.Finding(
                scan_id=scan.id,
                finding_hash=f"hash-{i:04d}",
                rule_id=fd["rule_id"],
                engine=fd["engine"],
                severity=fd["severity"],
                message=fd["message"],
                file_path=fd["file_path"],
                start_line=fd["start_line"],
                cwe_ids=fd["cwe_ids"],
                mois_id=fd["mois_id"],
                category=fd["category"],
                language="python" if fd["file_path"].endswith(".py") else "javascript",
                snippet=None,
                raw={},
                status="new",
            )
            session.add(row)
        session.commit()
        return {"scan_id": scan.id, "project_id": sample_project["id"]}
    finally:
        session.close()
