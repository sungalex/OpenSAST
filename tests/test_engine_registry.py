"""엔진 레지스트리 및 파이프라인 통합 테스트 (바이너리 없음 환경)."""

from __future__ import annotations

from pathlib import Path

from opensast.engines.registry import (
    ENGINE_CLASSES,
    FIRST_PASS_ENGINES,
    SECOND_PASS_ENGINES,
    available_engines,
    build_engine,
)
from opensast.orchestrator.pipeline import ScanOptions, run_scan


def test_registry_contains_all_engines() -> None:
    assert set(FIRST_PASS_ENGINES).issubset(ENGINE_CLASSES.keys())
    assert set(SECOND_PASS_ENGINES).issubset(ENGINE_CLASSES.keys())
    for name in ENGINE_CLASSES:
        engine = build_engine(name)
        assert engine.name == name


def test_availability_check_reports_all() -> None:
    infos = available_engines()
    names = {info.name for info in infos}
    assert names >= set(ENGINE_CLASSES.keys())


def test_pipeline_skips_missing_engines(tmp_path: Path) -> None:
    (tmp_path / "hello.py").write_text("print('hi')\n")
    result = run_scan(
        tmp_path,
        options=ScanOptions(enable_second_pass=False, enable_triage=False),
    )
    assert result.scan_id
    assert result.findings == []
