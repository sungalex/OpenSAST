"""SARIF 결과 파싱·정규화·병합 모듈."""

from opensast.sarif.merge import merge_findings
from opensast.sarif.normalize import findings_from_sarif, findings_to_sarif
from opensast.sarif.parser import SarifDocument, parse_sarif

__all__ = [
    "SarifDocument",
    "parse_sarif",
    "findings_from_sarif",
    "findings_to_sarif",
    "merge_findings",
]
