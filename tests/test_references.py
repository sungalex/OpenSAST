"""다중 레퍼런스(OWASP/SANS/PCI) 매핑 검증."""

from opensast.mois.references import (
    OWASP_TOP10_2021,
    SANS_TOP25_2023,
    references_for_cwe,
    references_for_cwes,
)


def test_owasp_catalog_contains_a01_to_a10() -> None:
    for i in range(1, 11):
        assert f"A{i:02d}" in OWASP_TOP10_2021


def test_sans_top25_size() -> None:
    assert len(SANS_TOP25_2023) == 25
    assert SANS_TOP25_2023["CWE-787"] == 1


def test_references_for_sql_injection() -> None:
    refs = references_for_cwe("CWE-89")
    standards = {r.standard for r in refs}
    assert "CWE" in standards
    assert "OWASP-2021" in standards
    assert "SANS-25" in standards
    # PCI-DSS 도 매핑됨
    assert "PCI-DSS-4.0" in standards


def test_normalization_accepts_int_and_string_forms() -> None:
    a = references_for_cwe("89")
    b = references_for_cwe("CWE-89")
    c = references_for_cwe("cwe-089")
    assert a and b and c
    assert {r.id for r in a} == {r.id for r in b} == {r.id for r in c}


def test_dedup_across_multiple_cwes() -> None:
    refs = references_for_cwes(["CWE-89", "CWE-79"])
    # Both A03 (Injection) — dedup to single OWASP entry
    owasp = [r for r in refs if r.standard == "OWASP-2021"]
    assert len(owasp) == 1
    assert owasp[0].id == "A03"
