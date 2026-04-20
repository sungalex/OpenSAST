"""MOIS 카탈로그 / 레퍼런스 표준 YAML 로더.

Python 하드코딩된 기본 카탈로그 위에 YAML 파일을 **merge** 할 수 있게 한다.
사용 시나리오:

- 기관이 행안부 가이드 개정판에 맞춰 항목을 추가/수정할 때
- 커스텀 CWE→OWASP/SANS 매핑이 필요할 때
- 특정 프로젝트 전용 레퍼런스를 더할 때

로드 순서:

1. 내장 Python 카탈로그 (`catalog.py::MOIS_ITEMS`)
2. (선택) `OPENSAST_MOIS_CATALOG_PATH` YAML — 동일 ID 덮어쓰기, 신규 ID 추가
3. (선택) `OPENSAST_REFERENCE_STANDARDS_PATH` YAML — CWE→표준 매핑 병합
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from opensast.config import get_settings
from opensast.mois.catalog import (
    MOIS_ITEMS,
    MoisCategory,
    MoisItem,
    Severity,
)
from opensast.utils.logging import get_logger

log = get_logger(__name__)


def load_mois_catalog() -> list[MoisItem]:
    """Python 기본 카탈로그 + YAML 오버레이 병합 결과 반환."""

    base: dict[str, MoisItem] = {item.id: item for item in MOIS_ITEMS}
    settings = get_settings()
    override_path = settings.mois_catalog_path
    if override_path and Path(override_path).exists():
        try:
            data = yaml.safe_load(Path(override_path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to load MOIS override %s: %s", override_path, exc)
            return list(base.values())
        for raw in data.get("items", []) or []:
            try:
                item = _item_from_dict(raw)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "skipping invalid MOIS override entry %s: %s",
                    raw.get("id"),
                    exc,
                )
                continue
            base[item.id] = item
            log.info("MOIS override loaded: %s", item.id)
    return list(base.values())


def _item_from_dict(raw: dict[str, Any]) -> MoisItem:
    return MoisItem(
        id=str(raw["id"]),
        name_kr=str(raw.get("name_kr") or raw.get("name") or raw["id"]),
        name_en=str(raw.get("name_en") or ""),
        category=MoisCategory(raw["category"]),
        cwe_ids=tuple(raw.get("cwe_ids") or ()),
        severity=Severity(raw.get("severity", "MEDIUM").upper()),
        primary_engines=tuple(raw.get("primary_engines") or ()),
        secondary_engines=tuple(raw.get("secondary_engines") or ()),
        description=str(raw.get("description") or ""),
    )


def load_reference_overlay() -> dict[str, list[dict[str, str]]]:
    """CWE → 추가 레퍼런스 태그 매핑 YAML 오버레이.

    Returns:
      { "CWE-89": [ {"standard": "PCI-DSS-4.0", "id": "6.2.4", ...}, ... ] }
    """

    settings = get_settings()
    path = settings.reference_standards_path
    if not path or not Path(path).exists():
        return {}
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        log.warning("failed to load reference overlay %s: %s", path, exc)
        return {}
    out: dict[str, list[dict[str, str]]] = {}
    for cwe, entries in (data.get("mappings") or {}).items():
        normalized = str(cwe).upper()
        out[normalized] = [dict(e) for e in entries if isinstance(e, dict)]
    return out
