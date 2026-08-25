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
from tests._credentials import BOOTSTRAP_PASSWORD


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
# H-6 / ADR-0008 — triage 상한과 실패 격리
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
# ADR-0006 — 설정 단일화
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
        bootstrap_admin_password=BOOTSTRAP_PASSWORD,
    ).apply_profile_defaults()
    assert s.enforce_startup_policy() == []
    assert s.auto_migrate_on_startup is False


def test_cloud_profile_rejects_wildcard_cors() -> None:
    from opensast.config import Profile, Settings

    s = Settings(
        profile=Profile.CLOUD,
        secret_key="a" * 64,
        cors_origins=["*"],
        bootstrap_admin_password=BOOTSTRAP_PASSWORD,
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


def test_no_naive_utcnow_anywhere_in_package() -> None:
    """패키지 전체에서 `datetime.utcnow()` 호출이 없어야 한다.

    처음 M-6 를 고칠 때 `db/repo.py` 만 보고 넘어갔는데, 정작 대다수 타임스탬프가
    나오는 `TimestampMixin` 의 컬럼 기본값이 `datetime.utcnow` 로 남아 있었다.
    그래서 검사 범위를 패키지 전체로 넓힌다.
    """

    import ast as _ast

    root = Path(__file__).resolve().parent.parent / "opensast"
    offenders: list[str] = []
    for py in sorted(root.rglob("*.py")):
        tree = _ast.parse(py.read_text(encoding="utf-8"))
        for node in _ast.walk(tree):
            # 호출: datetime.utcnow()
            if (
                isinstance(node, _ast.Call)
                and isinstance(node.func, _ast.Attribute)
                and node.func.attr == "utcnow"
            ):
                offenders.append(f"{py.relative_to(root)}:{node.lineno} (호출)")
            # 콜러블 참조: default=datetime.utcnow
            if (
                isinstance(node, _ast.Attribute)
                and node.attr == "utcnow"
                and isinstance(node.value, _ast.Name)
                and node.value.id == "datetime"
            ):
                offenders.append(f"{py.relative_to(root)}:{node.lineno} (참조)")
    assert offenders == [], "naive utcnow 사용: " + ", ".join(offenders)


def test_timestamp_columns_are_timezone_aware(db_session) -> None:
    """모델이 실제로 tz-aware 값을 쓰는지 확인한다.

    `DateTime(timezone=True)` 컬럼에 naive 값을 넣으면 Postgres 는 세션 타임존으로
    해석한다. 서버 타임존이 UTC 가 아니면 저장된 시각이 어긋나고, `audit_logs`
    처럼 증적이 되는 타임스탬프에서는 그대로 문제가 된다.
    """

    from opensast.db import models
    from opensast.db.base import utcnow

    assert utcnow().tzinfo is not None

    project = models.Project(name="tz-check", description="", repo_url="")
    db_session.add(project)
    db_session.flush()
    # flush 직후 파이썬 측 값이 aware 여야 한다 (SQLite 는 왕복 시 tzinfo 를
    # 보존하지 않으므로 저장 전 값을 본다).
    assert project.created_at.tzinfo is not None
    assert project.updated_at.tzinfo is not None


def test_no_deprecated_apis_in_package() -> None:
    """우리 코드가 deprecated API 를 직접 쓰지 않아야 한다.

    경고는 "지금 동작하니 괜찮다" 로 넘기기 쉽지만, 상위 라이브러리가 다음
    메이저에서 제거하면 그때는 기동 자체가 실패한다.

    문자열 매칭이 아니라 AST 로 본다 — 처음엔 문자열로 짰다가 설명용 docstring 을
    위반으로 잡는 오탐이 났다.
    """

    import ast as _ast

    root = Path(__file__).resolve().parent.parent / "opensast"
    on_event_uses: list[str] = []
    deprecated_status: list[str] = []

    for py in sorted(root.rglob("*.py")):
        tree = _ast.parse(py.read_text(encoding="utf-8"))
        for node in _ast.walk(tree):
            # FastAPI: @app.on_event(...) → lifespan 으로 대체됨
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    func = dec.func if isinstance(dec, _ast.Call) else dec
                    if (
                        isinstance(func, _ast.Attribute)
                        and func.attr == "on_event"
                    ):
                        on_event_uses.append(f"{py.relative_to(root)}:{node.lineno}")
            # starlette: HTTP_422_UNPROCESSABLE_ENTITY → ..._CONTENT
            # (getattr 폴백은 문자열 인자라 AST 상 Attribute 가 아니므로 잡히지 않는다)
            if (
                isinstance(node, _ast.Attribute)
                and node.attr == "HTTP_422_UNPROCESSABLE_ENTITY"
            ):
                deprecated_status.append(f"{py.relative_to(root)}:{node.lineno}")

    assert on_event_uses == [], f"on_event 는 deprecated (lifespan 사용): {on_event_uses}"
    # auth.py 의 getattr 폴백 1건은 허용 — 구버전 starlette 호환용
    assert len(deprecated_status) <= 1, (
        f"HTTP_422_UNPROCESSABLE_ENTITY 직접 참조: {deprecated_status}"
    )


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


# ---------------------------------------------------------------------------
# 시크릿 하드코딩 방지 (GitGuardian 지적)
# ---------------------------------------------------------------------------


def test_no_hardcoded_secret_literals_in_deployment_artifacts() -> None:
    """배포 산출물·예시 파일에 시크릿 리터럴이 없어야 한다.

    시크릿 스캐너(GitGuardian)가 잡는 문제이기도 하지만, 더 중요한 건 파일에 적힌
    값이 그대로 운영으로 흘러가기 쉽다는 점이다. 키는 주입하거나(운영)
    생성하지(개발) 파일에 적지 않는다.

    **범위 주의**: 부트스트랩 관리자 기본 비밀번호(`opensast-admin`)는 아직
    `config.py` 에 남아 있다. README 에 공개된 문서화된 기본값이라 "유출" 은
    아니지만, 기본 자격증명이 존재한다는 것 자체가 약점이다. 제거는 온보딩 동작을
    바꾸므로 별도 항목으로 ROADMAP 에 올려 두었다.
    """

    root = Path(__file__).resolve().parent.parent
    targets = [
        root / "docker-compose.yml",
        root / "docker-compose.prod.yml",
        root / ".env.example",
    ]
    forbidden = ("change-me-in-production", "opensast-admin")
    offenders = []
    for path in targets:
        if not path.exists():
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue  # 주석 안의 설명은 허용
            for needle in forbidden:
                if needle in line:
                    offenders.append(f"{path.name}:{i} ({needle})")
    assert offenders == [], "시크릿 리터럴: " + ", ".join(offenders)


def test_config_has_no_example_signing_key() -> None:
    """서명 키 예시 문자열이 소스에 없어야 한다."""

    config = (
        Path(__file__).resolve().parent.parent / "opensast" / "config.py"
    ).read_text(encoding="utf-8")
    assert "change-me-in-production" not in config


def test_empty_secret_key_never_signs_tokens() -> None:
    """빈 시크릿 키로 JWT 를 서명하는 상태가 없어야 한다.

    compose 에서 리터럴을 걷어내면서 `OPENSAST_SECRET_KEY=` (빈 값)이 주입될 수
    있게 됐다. 빈 키는 예시 키보다 나쁘므로 개발 프로파일은 임시 키를 생성한다.
    """

    from opensast.config import Profile, Settings

    for profile in (Profile.LOCAL, Profile.DOCKER):
        s = Settings(profile=profile, secret_key="").apply_profile_defaults()
        assert len(s.secret_key) >= 32, f"{profile.value}: 빈/약한 키"
        assert s.uses_ephemeral_secret is True
        # 임시 키 사용 사실이 경고로 드러나야 한다
        assert any("임시 키" in w for w in s.validate_profile())

    # cloud 는 임시 키를 쓰지 않고 기동을 거부한다
    c = Settings(
        profile=Profile.CLOUD,
        secret_key="",
        cors_origins=["https://x.example.com"],
        bootstrap_admin_password=BOOTSTRAP_PASSWORD,
    ).apply_profile_defaults()
    assert c.uses_ephemeral_secret is False
    with pytest.raises(RuntimeError):
        c.enforce_startup_policy()


def test_ephemeral_key_is_stable_within_process() -> None:
    """임시 키가 호출마다 바뀌면 같은 프로세스가 발급한 토큰도 검증에 실패한다."""

    from opensast.config import Profile, Settings

    a = Settings(profile=Profile.LOCAL, secret_key="").apply_profile_defaults()
    b = Settings(profile=Profile.LOCAL, secret_key="").apply_profile_defaults()
    assert a.secret_key == b.secret_key
