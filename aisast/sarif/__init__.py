"""SARIF 결과 파싱·정규화·병합 모듈."""

from aisast.sarif.merge import merge_findings
from aisast.sarif.normalize import findings_from_sarif, findings_to_sarif
from aisast.sarif.parser import SarifDocument, parse_sarif

__all__ = [
    "SarifDocument",
    "parse_sarif",
    "findings_from_sarif",
    "findings_to_sarif",
    "merge_findings",
]
