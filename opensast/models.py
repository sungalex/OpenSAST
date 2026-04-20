"""OpenSAST 핵심 도메인 모델.

SARIF·엔진·LLM 계층 모두가 참조하는 공통 Finding 표현. SQLAlchemy ORM과 별도로
관리하여 라이브러리 의존 없이 CLI·파이프라인 단독 사용이 가능하도록 한다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opensast.mois.catalog import MoisItem, Severity


@dataclass
class CodeLocation:
    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """엔진 독립 취약점 표현.

    `finding_id`는 엔진 결과 중복 제거를 위해 컨텐츠 해시로 산출한다.
    `mois_id`가 설정되어 있으면 행안부 점검표 상 특정 항목과 매핑됨을 의미하며,
    LLM 후처리 결과는 `triage` 필드에 누적된다.
    """

    rule_id: str
    engine: str
    message: str
    severity: Severity
    location: CodeLocation
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    mois_id: str | None = None
    category: str | None = None
    language: str | None = None
    finding_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    triage: "TriageResult | None" = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        payload = json.dumps(
            {
                "rule": self.rule_id,
                "engine": self.engine,
                "file": self.location.file_path,
                "line": self.location.start_line,
                "mois": self.mois_id,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "engine": self.engine,
            "message": self.message,
            "severity": self.severity.value,
            "location": self.location.as_dict(),
            "cwe_ids": list(self.cwe_ids),
            "mois_id": self.mois_id,
            "category": self.category,
            "language": self.language,
            "created_at": self.created_at.isoformat(),
        }
        if self.triage is not None:
            data["triage"] = self.triage.as_dict()
        return data

    def with_mois(self, item: MoisItem) -> "Finding":
        self.mois_id = item.id
        self.category = item.category.value
        if not self.cwe_ids:
            self.cwe_ids = item.cwe_ids
        return self


@dataclass
class TriageResult:
    verdict: str
    fp_probability: int
    rationale: str
    recommended_fix: str | None = None
    patched_code: str | None = None
    model: str = "unknown"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "fp_probability": self.fp_probability,
            "rationale": self.rationale,
            "recommended_fix": self.recommended_fix,
            "patched_code": self.patched_code,
            "model": self.model,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ScanTarget:
    root: Path
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = (".git/**", "node_modules/**", "**/*.min.js")
    language_hint: str | None = None


@dataclass
class ScanResult:
    scan_id: str
    target_root: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    engine_stats: dict[str, int]
    mois_coverage: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_root": self.target_root,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "engine_stats": self.engine_stats,
            "mois_coverage": self.mois_coverage,
            "findings": [f.as_dict() for f in self.findings],
        }
