"""행안부 카탈로그 구조 검증."""

from aisast.mois.catalog import (
    MOIS_ITEMS,
    MoisCategory,
    Severity,
    ensure_49_items,
    get_item,
    items_for_cwe,
)


def test_exactly_49_items() -> None:
    ensure_49_items()
    assert len(MOIS_ITEMS) == 49


def test_categories_distribution() -> None:
    counts: dict[MoisCategory, int] = {}
    for item in MOIS_ITEMS:
        counts[item.category] = counts.get(item.category, 0) + 1
    assert counts[MoisCategory.INPUT_VALIDATION] == 18
    assert counts[MoisCategory.SECURITY_FEATURE] == 12
    assert counts[MoisCategory.TIME_AND_STATE] == 2
    assert counts[MoisCategory.ERROR_HANDLING] == 3
    assert counts[MoisCategory.CODE_ERROR] == 7
    assert counts[MoisCategory.ENCAPSULATION] == 5
    assert counts[MoisCategory.API_MISUSE] == 2


def test_all_items_have_cwe_and_severity() -> None:
    for item in MOIS_ITEMS:
        assert item.cwe_ids, f"{item.id} missing CWE"
        assert isinstance(item.severity, Severity)
        assert item.primary_engines, f"{item.id} missing primary engines"


def test_get_item_and_cwe_lookup() -> None:
    sql = get_item("SR1-1")
    assert sql is not None
    assert "CWE-89" in sql.cwe_ids
    matches = items_for_cwe("CWE-89")
    assert any(m.id == "SR1-1" for m in matches)
    matches_normalized = items_for_cwe("89")
    assert any(m.id == "SR1-1" for m in matches_normalized)


def test_mois_ids_are_unique() -> None:
    ids = [item.id for item in MOIS_ITEMS]
    assert len(ids) == len(set(ids))
