"""아키텍처 진단에서 확인된 결함에 대한 회귀 테스트.

각 테스트는 실제로 존재했던 결함 하나에 대응한다.
"""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from opensast.mois.catalog import Severity
from opensast.models import CodeLocation, Finding, ScanResult
from opensast.services.base import ServiceError
from opensast.services.scan_service import ScanService, _is_contained


# ---------------------------------------------------------------------------
# H-2 — 경로 봉쇄를 문자열 접두사로 검사하던 문제
# ---------------------------------------------------------------------------


def test_sibling_prefix_is_not_contained(tmp_path: Path) -> None:
    """`/work/ab` 루트가 `/work/abcd` 를 통과시키면 안 된다."""

    root = tmp_path / "ab"
    sibling = tmp_path / "abcd"
    root.mkdir()
    sibling.mkdir()
    assert str(sibling).startswith(str(root))  # 예전 검사 방식은 통과시킨다
    assert not _is_contained(sibling, root)
    assert _is_contained(root / "x.py", root)
    assert _is_contained(root, root)


def test_read_source_blocks_sibling_prefix_escape(tmp_path: Path, db_session) -> None:
    from opensast.db import models
    from opensast.services.base import ActorContext

    root = tmp_path / "ab"
    root.mkdir()
    (tmp_path / "abcd").mkdir()
    (tmp_path / "abcd" / "secret.txt").write_text("classified")

    scan = models.Scan(
        id="pathscan001",
        project_id=1,
        source_path=str(root),
        status="completed",
    )
    svc = ScanService(db_session, ActorContext.system(reason="test"))
    db_session.add(models.Project(id=1, name="p", description="", repo_url=""))
    db_session.add(scan)
    db_session.commit()

    with pytest.raises(ServiceError, match="소스 루트를 벗어"):
        svc.read_source("pathscan001", path="../abcd/secret.txt")


# ---------------------------------------------------------------------------
# zip bomb / zip slip
# ---------------------------------------------------------------------------


def test_extract_rejects_zip_bomb(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", b"0" * (20 * 1024 * 1024))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ServiceError, match="압축 확대율"):
        ScanService._safe_extract_zip(archive, dest)


def test_extract_accepts_normal_archive(tmp_path: Path) -> None:
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.py", b"import os\n" * 50)
    dest = tmp_path / "out"
    dest.mkdir()
    ScanService._safe_extract_zip(archive, dest)
    assert (dest / "a.py").exists()


# ---------------------------------------------------------------------------
# H-4 — 알 수 없는 엔진이 스캔 전체를 크래시시키던 문제
# ---------------------------------------------------------------------------


def test_build_engine_raises_unknown_engine() -> None:
    from opensast.engines import UnknownEngine, build_engine

    with pytest.raises(UnknownEngine):
        build_engine("no-such-engine")


def test_pipeline_skips_unknown_engine(tmp_path: Path) -> None:
    """엔진 이름이 잘못돼도 파이프라인은 죽지 않고 건너뛴다."""

    from opensast.orchestrator.pipeline import ScanOptions, run_scan

    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(
        tmp_path,
        options=ScanOptions(
            engines=("no-such-engine",),
            enable_second_pass=False,
            enable_triage=False,
        ),
    )
    assert result.findings == []


# ---------------------------------------------------------------------------
# O1 — 2차 Pass 가 조용히 생략되던 문제
# ---------------------------------------------------------------------------


def test_second_pass_skip_is_reported(tmp_path: Path) -> None:
    from opensast.orchestrator.pipeline import ScanOptions, run_scan

    (tmp_path / "a.py").write_text("x = 1\n")
    result = run_scan(
        tmp_path,
        options=ScanOptions(
            engines=("bandit",),
            enable_second_pass=True,
            enable_triage=False,
        ),
    )
    assert any("2차 Pass" in n for n in result.notes)


# ---------------------------------------------------------------------------
# H-5 — 저장 멱등성
# ---------------------------------------------------------------------------


def _result_with(scan_id: str, findings: list[Finding]) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(
        scan_id=scan_id,
        target_root="/tmp/x",
        started_at=now,
        finished_at=now,
        findings=findings,
        engine_stats={},
        mois_coverage={},
    )


def test_persist_scan_result_is_idempotent(db_session) -> None:
    from opensast.db import models, repo

    db_session.add(models.Project(id=1, name="p", description="", repo_url=""))
    db_session.add(
        models.Scan(id="idem00000001", project_id=1, source_path="/tmp/x", status="queued")
    )
    db_session.commit()

    finding = Finding(
        rule_id="r1",
        engine="opengrep",
        message="m",
        severity=Severity.HIGH,
        location=CodeLocation(file_path="a.py", start_line=1),
        cwe_ids=("CWE-89",),
    )
    result = _result_with("idem00000001", [finding])

    first = repo.persist_scan_result(db_session, "idem00000001", result)
    db_session.commit()
    second = repo.persist_scan_result(db_session, "idem00000001", result)
    db_session.commit()

    assert first == 1
    assert second == 0
    assert repo.count_findings_for_scan(db_session, "idem00000001") == 1


# ---------------------------------------------------------------------------
# M-3 — severity 정렬이 알파벳순이던 문제
# ---------------------------------------------------------------------------


def test_findings_are_ordered_high_medium_low(db_session) -> None:
    from opensast.db import models, repo

    db_session.add(models.Project(id=1, name="p", description="", repo_url=""))
    db_session.add(
        models.Scan(id="ord000000001", project_id=1, source_path="/tmp/x", status="completed")
    )
    db_session.flush()
    for i, sev in enumerate(["LOW", "MEDIUM", "HIGH"]):
        db_session.add(
            models.Finding(
                scan_id="ord000000001",
                finding_hash=f"h{i}",
                rule_id="r",
                engine="e",
                message="m",
                severity=sev,
                file_path="a.py",
                start_line=i + 1,
                cwe_ids=[],
                raw={},
            )
        )
    db_session.commit()

    rows = repo.list_findings_for_scan(db_session, "ord000000001")
    assert [r.severity for r in rows] == ["HIGH", "MEDIUM", "LOW"]


def test_list_findings_no_silent_truncation(db_session) -> None:
    """limit 을 주지 않으면 전부 반환해야 한다 (예전 기본 1000 하드캡)."""

    import inspect

    from opensast.db import repo

    sig = inspect.signature(repo.list_findings_for_scan)
    assert sig.parameters["limit"].default is None


# ---------------------------------------------------------------------------
# M-1 — 병합이 CWE 없는 서로 다른 규칙을 합치던 문제
# ---------------------------------------------------------------------------


def test_merge_preserves_distinct_rules_without_cwe() -> None:
    from opensast.sarif.merge import merge_findings

    def _f(rule_id: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            engine="opengrep",
            message=rule_id,
            severity=Severity.MEDIUM,
            location=CodeLocation(file_path="a.py", start_line=10),
            cwe_ids=(),
        )

    merged = merge_findings([[_f("rule-a"), _f("rule-b")]])
    assert {f.rule_id for f in merged} == {"rule-a", "rule-b"}


def test_merge_still_dedupes_same_cwe_same_location() -> None:
    from opensast.sarif.merge import merge_findings

    def _f(engine: str) -> Finding:
        return Finding(
            rule_id=f"{engine}-rule",
            engine=engine,
            message="sql",
            severity=Severity.HIGH,
            location=CodeLocation(file_path="a.py", start_line=10),
            cwe_ids=("CWE-89",),
        )

    merged = merge_findings([[_f("opengrep")], [_f("codeql")]])
    assert len(merged) == 1
    assert merged[0].engine == "codeql"  # 우선순위가 높은 엔진이 남는다


# ---------------------------------------------------------------------------
# M-2 — triage 컨텍스트가 소스 루트 밖 파일을 읽던 문제
# ---------------------------------------------------------------------------


def test_triage_context_blocks_path_escape(tmp_path: Path) -> None:
    from opensast.llm.noop import NoopLLMClient
    from opensast.llm.triage import Triager

    root = tmp_path / "src"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET CONTENT")

    finding = Finding(
        rule_id="r",
        engine="opengrep",
        message="m",
        severity=Severity.HIGH,
        location=CodeLocation(
            file_path="../secret.txt", start_line=1, snippet="safe-snippet"
        ),
        cwe_ids=(),
    )
    ctx = Triager(client=NoopLLMClient())._collect_context(finding, root)
    assert "TOP SECRET" not in ctx.code_context
    assert ctx.code_context == "safe-snippet"


# ---------------------------------------------------------------------------
# H-6 / ADR-004 — triage 상한과 실패 격리
# ---------------------------------------------------------------------------


def test_triage_truncation_is_reported(monkeypatch) -> None:
    from opensast.llm.noop import NoopLLMClient
    from opensast.llm.triage import Triager

    triager = Triager(client=NoopLLMClient())
    monkeypatch.setattr(triager.settings, "triage_max_findings", 2)
    monkeypatch.setattr(triager.settings, "triage_cache_ttl_seconds", 0)

    findings = [
        Finding(
            rule_id=f"r{i}",
            engine="opengrep",
            message="m",
            severity=Severity.LOW if i > 0 else Severity.HIGH,
            location=CodeLocation(file_path=f"a{i}.py", start_line=1),
            cwe_ids=(),
        )
        for i in range(5)
    ]
    triager.triage(findings)
    report = triager.last_report
    assert report.truncated == 3
    assert report.notes and "상한" in report.notes[0]
    # HIGH 는 반드시 판정 대상에 포함된다
    assert findings[0].triage is not None


def test_triage_isolates_non_llm_failures(monkeypatch) -> None:
    """LLMError 외의 예외 하나가 나머지 Finding 판정을 날리면 안 된다."""

    from opensast.llm.noop import NoopLLMClient
    from opensast.llm.triage import Triager

    triager = Triager(client=NoopLLMClient())
    monkeypatch.setattr(triager.settings, "triage_cache_ttl_seconds", 0)
    monkeypatch.setattr(triager.settings, "llm_max_concurrency", 1)

    calls = {"n": 0}
    original = triager._collect_context

    def flaky(finding, source_root):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")  # LLMError 가 아닌 예외
        return original(finding, source_root)

    monkeypatch.setattr(triager, "_collect_context", flaky)

    findings = [
        Finding(
            rule_id=f"r{i}",
            engine="opengrep",
            message="m",
            severity=Severity.HIGH,
            location=CodeLocation(file_path=f"a{i}.py", start_line=1),
            cwe_ids=(),
        )
        for i in range(3)
    ]
    triager.triage(findings)
    assert all(f.triage is not None for f in findings)
    assert triager.last_report.failed == 1
    assert triager.last_report.triaged == 2


def test_triage_cache_failure_is_reported_once(monkeypatch) -> None:
    """Redis 실패가 조용히 삼켜지지 않고 경고 후 캐시가 꺼져야 한다.

    로깅 설정이 테스트 간에 달라질 수 있으므로 `caplog` 대신 모듈 로거를 직접
    가로채 검증한다 — 검증 대상은 "경고를 남기는가" 이지 "어느 핸들러로 가는가"
    가 아니다.
    """

    from opensast.llm import triage as triage_mod
    from opensast.llm.noop import NoopLLMClient

    class _Broken:
        def get(self, *a, **k):
            raise ConnectionError("no redis here")

        def set(self, *a, **k):
            raise ConnectionError("no redis here")

    warnings: list[str] = []

    class _Recorder:
        def warning(self, msg, *args):
            warnings.append(msg % args if args else msg)

        def __getattr__(self, _name):
            return lambda *a, **k: None

    monkeypatch.setattr(triage_mod, "_redis_client", lambda url: _Broken())
    monkeypatch.setattr(triage_mod, "log", _Recorder())

    triager = triage_mod.Triager(client=NoopLLMClient())
    monkeypatch.setattr(triager.settings, "triage_cache_ttl_seconds", 86400)

    finding = Finding(
        rule_id="r",
        engine="opengrep",
        message="m",
        severity=Severity.HIGH,
        location=CodeLocation(file_path="a.py", start_line=1),
        cwe_ids=(),
    )
    triager.triage([finding])

    cache_warnings = [w for w in warnings if "캐시 비활성화" in w]
    assert len(cache_warnings) == 1, warnings
    assert "OPENSAST_REDIS_URL" in cache_warnings[0]
    assert triager.last_report.cache_enabled is False


# ---------------------------------------------------------------------------
# ADR-002 — 설정 단일화
# ---------------------------------------------------------------------------


def test_db_pool_size_is_actually_wired() -> None:
    from opensast.config import Settings
    from opensast.db.session import _engine_kwargs

    kwargs = _engine_kwargs(
        Settings(database_url="postgresql+psycopg2://u:p@h/db", db_pool_size=17)
    )
    assert kwargs["pool_size"] == 17


def test_cloud_profile_refuses_unsafe_startup() -> None:
    from opensast.config import Profile, Settings

    s = Settings(profile=Profile.CLOUD).apply_profile_defaults()
    with pytest.raises(RuntimeError, match="안전하지 않은 설정"):
        s.enforce_startup_policy()


def test_cloud_profile_starts_with_safe_values() -> None:
    from opensast.config import Profile, Settings

    s = Settings(
        profile=Profile.CLOUD,
        secret_key="a" * 64,
        cors_origins=["https://sast.example.com"],
        bootstrap_admin_password="Str0ng-Bootstrap#1",
    ).apply_profile_defaults()
    assert s.enforce_startup_policy() == []
    assert s.auto_migrate_on_startup is False


def test_cloud_profile_rejects_wildcard_cors() -> None:
    from opensast.config import Profile, Settings

    s = Settings(
        profile=Profile.CLOUD,
        secret_key="a" * 64,
        cors_origins=["*"],
        bootstrap_admin_password="Str0ng-Bootstrap#1",
    ).apply_profile_defaults()
    assert any("와일드카드" in w for w in s.validate_profile())


def test_overlay_config_is_applied(tmp_path: Path, monkeypatch) -> None:
    """ARCHITECTURE §5.5 의 설정 오버레이가 실제로 동작해야 한다.

    `isolate_from_dotenv` 픽스처(autouse)가 리포지토리 `.env` 를 끊어 주므로
    개발자 머신의 `.env` 내용과 무관하게 같은 결과가 나온다.
    """

    from opensast.config import get_settings, reset_settings_cache

    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(
        "llm:\n  provider: noop\n  max_concurrency: 9\nrate_limit_per_minute: 7\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSAST_OVERLAY_CONFIG", str(overlay))
    monkeypatch.setenv("OPENSAST_PROFILE", "local")
    reset_settings_cache()

    s = get_settings()
    # 1단계 중첩 섹션이 `섹션_키` 로 평탄화된다
    assert s.llm_provider == "noop"
    assert s.llm_max_concurrency == 9
    # 평탄한 키도 그대로 적용된다 (프로파일 기본값 0 을 덮어씀)
    assert s.rate_limit_per_minute == 7


def test_environment_beats_overlay(tmp_path: Path, monkeypatch) -> None:
    """문서화된 우선순위: 프로파일 기본값 → 오버레이 → 환경변수.

    이 테스트가 없어서, `.env` 가 오버레이를 이기는 **정상 동작**을
    버그로 오해할 뻔했다.
    """

    from opensast.config import get_settings, reset_settings_cache

    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(
        "llm:\n  provider: noop\nrate_limit_per_minute: 7\n", encoding="utf-8"
    )
    monkeypatch.setenv("OPENSAST_OVERLAY_CONFIG", str(overlay))
    monkeypatch.setenv("OPENSAST_PROFILE", "local")
    # 환경변수가 오버레이와 충돌하는 값을 지정
    monkeypatch.setenv("OPENSAST_LLM_PROVIDER", "anthropic")
    reset_settings_cache()

    s = get_settings()
    assert s.llm_provider == "anthropic"      # 환경변수가 이긴다
    assert s.rate_limit_per_minute == 7       # 충돌 없는 키는 오버레이가 적용된다


def test_overlay_ignores_unknown_keys(tmp_path: Path, monkeypatch, caplog) -> None:
    """오타가 조용히 삼켜지지 않아야 한다."""

    import logging

    from opensast.config import load_overlay

    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(
        "llm:\n  provdier: noop\nrate_limit_per_minute: 7\n", encoding="utf-8"
    )
    with caplog.at_level(logging.WARNING):
        parsed = load_overlay(overlay)
    assert parsed == {"rate_limit_per_minute": 7}
    assert "llm_provdier" in caplog.text


def test_upload_limit_comes_from_settings() -> None:
    """서비스가 하드코딩 상수 대신 설정을 읽어야 한다."""

    import inspect

    source = inspect.getsource(ScanService._stream_upload)
    assert "self.settings.max_upload_bytes" in source


# ---------------------------------------------------------------------------
# H-1 — /ready 가 존재하지 않는 모듈을 import 하던 문제
# ---------------------------------------------------------------------------


def test_ready_endpoint_imports_real_celery_module() -> None:
    import inspect

    from opensast.api import app as app_mod

    source = inspect.getsource(app_mod.create_app)
    assert "opensast.worker" not in source
    assert "opensast.orchestrator.celery_app" in source


# ---------------------------------------------------------------------------
# M-6 — naive/aware datetime 혼용
# ---------------------------------------------------------------------------


def test_repo_uses_timezone_aware_utc() -> None:
    """repo 가 naive `datetime.utcnow()` 를 쓰지 않아야 한다.

    값 자체는 aware 로 기록되지만, SQLite 는 tzinfo 를 보존하지 않으므로
    라운드트립이 아니라 소스와 헬퍼 수준에서 검증한다 (Postgres 에서는
    `TIMESTAMPTZ` 로 보존된다).
    """

    import inspect

    from opensast.db import repo

    assert repo._utcnow().tzinfo is not None

    # 주석/문서가 아니라 실제 호출을 본다.
    import ast

    tree = ast.parse(inspect.getsource(repo))
    naive_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "utcnow"
    ]
    assert naive_calls == []


def test_importing_api_does_not_build_app(tmp_path: Path) -> None:
    """`opensast.api` import 만으로 앱이 생성되면 안 된다.

    예전에는 `app.py` 최상단에서 `create_app()` 을 실행해, 토큰 헬퍼 하나를
    import 하는 것만으로 설정 검증·DB 엔진·플러그인 탐색이 전부 돌았다.
    cloud 프로파일에서는 그 검증이 기동 실패를 던지므로 테스트 수집이
    통째로 중단됐다.

    하위 프로세스를 임시 디렉터리에서 돌려 리포지토리 `.env` 로부터 격리한다 —
    개발자의 `.env` 내용과 무관하게 같은 결과가 나와야 한다.
    """

    import os
    import subprocess
    import sys

    code = (
        "import opensast.api.app as m\n"
        "from opensast.api.security import create_access_token\n"
        "assert m._app is None, 'import 만으로 앱이 생성됨'\n"
        "first = m.app\n"
        "assert m._app is not None, 'app 접근 후에도 생성되지 않음'\n"
        "assert m.app is first, '접근할 때마다 새 앱이 생성됨'\n"
        "print('OK')\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENSAST_")}
    env["OPENSAST_PROFILE"] = "local"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
