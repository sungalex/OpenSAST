"""MOIS 카탈로그 / 레퍼런스 YAML 오버레이 로더 검증."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisast.mois import references


def test_load_mois_catalog_without_override(monkeypatch: pytest.MonkeyPatch) -> None:
    from aisast.config import reset_settings_cache
    from aisast.mois.loader import load_mois_catalog

    monkeypatch.delenv("AISAST_MOIS_CATALOG_PATH", raising=False)
    reset_settings_cache()
    items = load_mois_catalog()
    assert len(items) == 49  # 내장 카탈로그 그대로


def test_load_mois_catalog_applies_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aisast.config import reset_settings_cache
    from aisast.mois.loader import load_mois_catalog

    overlay = tmp_path / "mois.yaml"
    overlay.write_text(
        """
items:
  - id: "SR1-1"
    name_kr: "SQL 삽입(오버라이드)"
    name_en: "SQL Injection"
    category: "입력데이터 검증 및 표현"
    cwe_ids: ["CWE-89"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
  - id: "ORG-001"
    name_kr: "사내 룰"
    name_en: "Internal"
    category: "보안기능"
    cwe_ids: ["CWE-798"]
    severity: "HIGH"
    primary_engines: ["opengrep"]
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AISAST_MOIS_CATALOG_PATH", str(overlay))
    reset_settings_cache()

    items = load_mois_catalog()
    by_id = {i.id: i for i in items}
    assert "ORG-001" in by_id  # 신규 항목 추가
    assert "오버라이드" in by_id["SR1-1"].name_kr  # 기존 항목 덮어쓰기
    assert len(items) == 50  # 49 + 1


def test_reference_overlay_adds_custom_standards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aisast.config import reset_settings_cache

    overlay = tmp_path / "refs.yaml"
    overlay.write_text(
        """
mappings:
  "CWE-89":
    - standard: "KISA-KSG-2024"
      id: "DB-001"
      title: "DB 입력 검증"
      url: ""
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AISAST_REFERENCE_STANDARDS_PATH", str(overlay))
    reset_settings_cache()
    references.reset_overlay_cache()

    tags = references.references_for_cwe("CWE-89")
    standards = [t.standard for t in tags]
    assert "KISA-KSG-2024" in standards
