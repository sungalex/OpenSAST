"""MOIS 외 외부 보안 표준 레퍼런스 매핑.

Sparrow SAST/SAQT가 제공하는 '레퍼런스 분류' 기능을 대체하여 aiSAST는 다음 표준을
MOIS 49개 항목과 함께 관리한다:

  * CWE (MITRE Common Weakness Enumeration)
  * OWASP Top 10 2021
  * SANS/CWE Top 25 (2023)
  * PCI DSS v4.0 (주요 요구사항)

CWE ID 하나가 여러 표준에 걸쳐 있을 수 있으며, 본 모듈은 CWE 를 키로 역매핑을
제공해 Finding 이 탐지되면 자동으로 여러 레퍼런스 배지가 부착되도록 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ReferenceTag:
    """단일 표준 항목."""

    standard: str  # 예: "OWASP-2021", "SANS-25", "CWE", "PCI-DSS"
    id: str  # 예: "A03", "CWE-89"
    title: str  # 예: "Injection"
    url: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "standard": self.standard,
            "id": self.id,
            "title": self.title,
            "url": self.url,
        }


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) — https://owasp.org/Top10/
# ---------------------------------------------------------------------------
OWASP_TOP10_2021: dict[str, ReferenceTag] = {
    "A01": ReferenceTag(
        "OWASP-2021",
        "A01",
        "Broken Access Control",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    "A02": ReferenceTag(
        "OWASP-2021",
        "A02",
        "Cryptographic Failures",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ),
    "A03": ReferenceTag(
        "OWASP-2021",
        "A03",
        "Injection",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ),
    "A04": ReferenceTag(
        "OWASP-2021",
        "A04",
        "Insecure Design",
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    ),
    "A05": ReferenceTag(
        "OWASP-2021",
        "A05",
        "Security Misconfiguration",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    "A06": ReferenceTag(
        "OWASP-2021",
        "A06",
        "Vulnerable and Outdated Components",
        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    ),
    "A07": ReferenceTag(
        "OWASP-2021",
        "A07",
        "Identification and Authentication Failures",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    "A08": ReferenceTag(
        "OWASP-2021",
        "A08",
        "Software and Data Integrity Failures",
        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    ),
    "A09": ReferenceTag(
        "OWASP-2021",
        "A09",
        "Security Logging and Monitoring Failures",
        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ),
    "A10": ReferenceTag(
        "OWASP-2021",
        "A10",
        "Server-Side Request Forgery (SSRF)",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
}

# CWE → OWASP Top 10 2021 매핑 (대표적인 것만)
CWE_TO_OWASP: dict[str, str] = {
    # A01 Broken Access Control
    "CWE-22": "A01",
    "CWE-23": "A01",
    "CWE-35": "A01",
    "CWE-59": "A01",
    "CWE-201": "A01",
    "CWE-275": "A01",
    "CWE-276": "A01",
    "CWE-284": "A01",
    "CWE-285": "A01",
    "CWE-352": "A01",
    "CWE-359": "A01",
    "CWE-377": "A01",
    "CWE-402": "A01",
    "CWE-425": "A01",
    "CWE-441": "A01",
    "CWE-497": "A01",
    "CWE-538": "A01",
    "CWE-540": "A01",
    "CWE-552": "A01",
    "CWE-566": "A01",
    "CWE-601": "A01",
    "CWE-639": "A01",
    "CWE-651": "A01",
    "CWE-668": "A01",
    "CWE-706": "A01",
    "CWE-862": "A01",
    "CWE-863": "A01",
    "CWE-913": "A01",
    "CWE-922": "A01",
    "CWE-1275": "A01",
    # A02 Cryptographic Failures
    "CWE-259": "A02",
    "CWE-296": "A02",
    "CWE-310": "A02",
    "CWE-311": "A02",
    "CWE-312": "A02",
    "CWE-319": "A02",
    "CWE-321": "A02",
    "CWE-322": "A02",
    "CWE-323": "A02",
    "CWE-324": "A02",
    "CWE-325": "A02",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-328": "A02",
    "CWE-329": "A02",
    "CWE-330": "A02",
    "CWE-331": "A02",
    "CWE-335": "A02",
    "CWE-336": "A02",
    "CWE-337": "A02",
    "CWE-338": "A02",
    "CWE-340": "A02",
    "CWE-347": "A02",
    "CWE-523": "A02",
    "CWE-720": "A02",
    "CWE-757": "A02",
    "CWE-759": "A02",
    "CWE-760": "A02",
    "CWE-780": "A02",
    "CWE-818": "A02",
    "CWE-916": "A02",
    # A03 Injection
    "CWE-20": "A03",
    "CWE-74": "A03",
    "CWE-75": "A03",
    "CWE-77": "A03",
    "CWE-78": "A03",
    "CWE-79": "A03",
    "CWE-80": "A03",
    "CWE-83": "A03",
    "CWE-87": "A03",
    "CWE-88": "A03",
    "CWE-89": "A03",
    "CWE-90": "A03",
    "CWE-91": "A03",
    "CWE-93": "A03",
    "CWE-94": "A03",
    "CWE-95": "A03",
    "CWE-96": "A03",
    "CWE-97": "A03",
    "CWE-98": "A03",
    "CWE-99": "A03",
    "CWE-113": "A03",
    "CWE-116": "A03",
    "CWE-138": "A03",
    "CWE-184": "A03",
    "CWE-470": "A03",
    "CWE-471": "A03",
    "CWE-564": "A03",
    "CWE-610": "A03",
    "CWE-643": "A03",
    "CWE-644": "A03",
    "CWE-652": "A03",
    "CWE-917": "A03",
    # A04 Insecure Design (partial)
    "CWE-209": "A04",
    "CWE-256": "A04",
    "CWE-501": "A04",
    "CWE-522": "A04",
    # A05 Security Misconfiguration
    "CWE-2": "A05",
    "CWE-11": "A05",
    "CWE-13": "A05",
    "CWE-15": "A05",
    "CWE-16": "A05",
    "CWE-260": "A05",
    "CWE-315": "A05",
    "CWE-520": "A05",
    "CWE-526": "A05",
    "CWE-537": "A05",
    "CWE-541": "A05",
    "CWE-547": "A05",
    "CWE-611": "A05",
    "CWE-614": "A05",
    "CWE-756": "A05",
    "CWE-776": "A05",
    "CWE-942": "A05",
    "CWE-1004": "A05",
    "CWE-1032": "A05",
    "CWE-1174": "A05",
    # A06 Vulnerable Components
    "CWE-937": "A06",
    "CWE-1035": "A06",
    "CWE-1104": "A06",
    # A07 Identification & Authentication
    "CWE-255": "A07",
    "CWE-287": "A07",
    "CWE-288": "A07",
    "CWE-290": "A07",
    "CWE-294": "A07",
    "CWE-295": "A07",
    "CWE-297": "A07",
    "CWE-300": "A07",
    "CWE-302": "A07",
    "CWE-304": "A07",
    "CWE-306": "A07",
    "CWE-307": "A07",
    "CWE-346": "A07",
    "CWE-384": "A07",
    "CWE-521": "A07",
    "CWE-613": "A07",
    "CWE-620": "A07",
    "CWE-640": "A07",
    "CWE-798": "A07",
    "CWE-940": "A07",
    "CWE-1216": "A07",
    # A08 Software and Data Integrity Failures
    "CWE-345": "A08",
    "CWE-353": "A08",
    "CWE-426": "A08",
    "CWE-494": "A08",
    "CWE-502": "A08",
    "CWE-565": "A08",
    "CWE-784": "A08",
    "CWE-829": "A08",
    "CWE-830": "A08",
    "CWE-915": "A08",
    # A09 Logging
    "CWE-117": "A09",
    "CWE-223": "A09",
    "CWE-532": "A09",
    "CWE-778": "A09",
    # A10 SSRF
    "CWE-918": "A10",
}


# ---------------------------------------------------------------------------
# SANS/CWE Top 25 (2023)
# ---------------------------------------------------------------------------
SANS_TOP25_2023: dict[str, int] = {
    "CWE-787": 1,
    "CWE-79": 2,
    "CWE-89": 3,
    "CWE-416": 4,
    "CWE-78": 5,
    "CWE-20": 6,
    "CWE-125": 7,
    "CWE-22": 8,
    "CWE-352": 9,
    "CWE-434": 10,
    "CWE-862": 11,
    "CWE-476": 12,
    "CWE-287": 13,
    "CWE-190": 14,
    "CWE-502": 15,
    "CWE-77": 16,
    "CWE-119": 17,
    "CWE-798": 18,
    "CWE-918": 19,
    "CWE-306": 20,
    "CWE-362": 21,
    "CWE-269": 22,
    "CWE-94": 23,
    "CWE-863": 24,
    "CWE-276": 25,
}


# ---------------------------------------------------------------------------
# PCI DSS v4.0 핵심 요구사항 매핑 (보안 개발 관점)
# ---------------------------------------------------------------------------
CWE_TO_PCI_DSS: dict[str, str] = {
    "CWE-89": "6.2.4",
    "CWE-79": "6.2.4",
    "CWE-78": "6.2.4",
    "CWE-22": "6.2.4",
    "CWE-352": "6.2.4",
    "CWE-434": "6.2.4",
    "CWE-502": "6.2.4",
    "CWE-798": "8.3.2",
    "CWE-259": "8.3.2",
    "CWE-327": "4.2.1",
    "CWE-326": "4.2.1",
    "CWE-311": "3.5.1",
    "CWE-312": "3.5.1",
    "CWE-319": "4.2.1",
}


def references_for_cwe(cwe_id: str) -> list[ReferenceTag]:
    """단일 CWE 에 대응되는 모든 표준 레퍼런스 반환."""

    cwe = _normalize(cwe_id)
    if not cwe:
        return []
    tags: list[ReferenceTag] = [
        ReferenceTag(
            standard="CWE",
            id=cwe,
            title=cwe,
            url=f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html",
        )
    ]
    owasp_id = CWE_TO_OWASP.get(cwe)
    if owasp_id and owasp_id in OWASP_TOP10_2021:
        tags.append(OWASP_TOP10_2021[owasp_id])
    rank = SANS_TOP25_2023.get(cwe)
    if rank is not None:
        tags.append(
            ReferenceTag(
                standard="SANS-25",
                id=f"#{rank}",
                title=f"SANS/CWE Top 25 #{rank}",
                url="https://www.sans.org/top25-software-errors/",
            )
        )
    pci = CWE_TO_PCI_DSS.get(cwe)
    if pci:
        tags.append(
            ReferenceTag(
                standard="PCI-DSS-4.0",
                id=pci,
                title=f"PCI DSS v4.0 §{pci}",
                url="https://www.pcisecuritystandards.org/",
            )
        )
    return tags


def references_for_cwes(cwes: Iterable[str]) -> list[ReferenceTag]:
    seen: dict[tuple[str, str], ReferenceTag] = {}
    for cwe in cwes:
        for tag in references_for_cwe(cwe):
            key = (tag.standard, tag.id)
            if key not in seen:
                seen[key] = tag
    return list(seen.values())


def _normalize(cwe: str) -> str:
    cwe = (cwe or "").strip().upper()
    if not cwe:
        return ""
    if cwe.isdigit():
        return f"CWE-{int(cwe)}"
    if cwe.startswith("CWE-") and cwe[4:].isdigit():
        return f"CWE-{int(cwe[4:])}"
    return cwe
