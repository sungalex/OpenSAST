"""SARIF 2.1.0 문서 파서.

모든 엔진(Opengrep, Bandit, ESLint, gosec, SpotBugs, CodeQL)은 SARIF 출력을
지원하므로 이 파서가 유일한 입력 진입점이다. 본 구현은 SARIF 핵심 서브셋만
처리하며, 파서 실패 시 경고 로그를 남기고 빈 결과를 반환한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aisast.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class SarifRule:
    id: str
    name: str | None = None
    short_description: str | None = None
    full_description: str | None = None
    help_uri: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class SarifLocation:
    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    snippet: str | None = None


@dataclass
class SarifResult:
    rule_id: str
    message: str
    level: str
    location: SarifLocation
    rule: SarifRule | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SarifRun:
    tool_name: str
    tool_version: str | None
    results: list[SarifResult]
    rules_index: dict[str, SarifRule]


@dataclass
class SarifDocument:
    runs: list[SarifRun]

    @property
    def results(self) -> list[SarifResult]:
        out: list[SarifResult] = []
        for run in self.runs:
            out.extend(run.results)
        return out


def parse_sarif(path: Path | str) -> SarifDocument:
    """파일에서 SARIF 문서 파싱."""

    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        log.warning("SARIF file not found: %s", path)
        return SarifDocument(runs=[])
    except json.JSONDecodeError as exc:
        log.warning("Malformed SARIF %s: %s", path, exc)
        return SarifDocument(runs=[])
    return parse_sarif_dict(raw)


def parse_sarif_dict(raw: dict[str, Any]) -> SarifDocument:
    runs: list[SarifRun] = []
    for run_raw in raw.get("runs", []) or []:
        tool = run_raw.get("tool", {}).get("driver", {})
        tool_name = tool.get("name") or "unknown"
        tool_version = tool.get("version") or tool.get("semanticVersion")
        rules_raw = tool.get("rules") or []
        rules_index: dict[str, SarifRule] = {}
        for rule_raw in rules_raw:
            rule = _parse_rule(rule_raw)
            rules_index[rule.id] = rule
        results: list[SarifResult] = []
        for result_raw in run_raw.get("results", []) or []:
            parsed = _parse_result(result_raw, rules_index)
            if parsed is not None:
                results.append(parsed)
        runs.append(
            SarifRun(
                tool_name=tool_name,
                tool_version=tool_version,
                results=results,
                rules_index=rules_index,
            )
        )
    return SarifDocument(runs=runs)


def _parse_rule(rule_raw: dict[str, Any]) -> SarifRule:
    rule_id = rule_raw.get("id") or rule_raw.get("name") or "unknown"
    name = rule_raw.get("name")
    short = _text_of(rule_raw.get("shortDescription"))
    full = _text_of(rule_raw.get("fullDescription"))
    help_uri = rule_raw.get("helpUri")
    props = rule_raw.get("properties") or {}
    tags_raw = props.get("tags") or []
    tags = tuple(str(t) for t in tags_raw)
    cwe_ids = _extract_cwes(tags_raw, props)
    return SarifRule(
        id=rule_id,
        name=name,
        short_description=short,
        full_description=full,
        help_uri=help_uri,
        tags=tags,
        cwe_ids=cwe_ids,
    )


def _parse_result(
    result_raw: dict[str, Any], rules_index: dict[str, SarifRule]
) -> SarifResult | None:
    rule_id = result_raw.get("ruleId") or result_raw.get("rule", {}).get("id")
    if not rule_id:
        return None
    message = _text_of(result_raw.get("message")) or ""
    level = (result_raw.get("level") or "warning").lower()
    locations = result_raw.get("locations") or []
    location = _first_location(locations)
    if location is None:
        return None
    return SarifResult(
        rule_id=rule_id,
        message=message,
        level=level,
        location=location,
        rule=rules_index.get(rule_id),
        properties=result_raw.get("properties") or {},
    )


def _first_location(locations: list[dict[str, Any]]) -> SarifLocation | None:
    for loc in locations:
        phys = loc.get("physicalLocation") or {}
        artifact = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}
        uri = artifact.get("uri")
        start_line = region.get("startLine") or 1
        if not uri:
            continue
        return SarifLocation(
            file_path=uri,
            start_line=int(start_line),
            end_line=region.get("endLine"),
            start_column=region.get("startColumn"),
            end_column=region.get("endColumn"),
            snippet=_text_of(region.get("snippet")),
        )
    return None


def _text_of(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return val.get("text") or val.get("markdown")
    return None


def _extract_cwes(
    tags: list[Any], props: dict[str, Any]
) -> tuple[str, ...]:
    out: list[str] = []
    for tag in tags:
        if isinstance(tag, str) and tag.lower().startswith("cwe"):
            out.append(tag.upper().replace("CWE:", "CWE-").replace("_", "-"))
    for key in ("cwe", "cwe_ids", "security-severity-cwe"):
        val = props.get(key)
        if isinstance(val, str):
            out.append(val.upper())
        elif isinstance(val, list):
            out.extend(str(v).upper() for v in val)
    normalized: list[str] = []
    for raw in out:
        raw = raw.strip().upper()
        if raw.startswith("CWE-") and raw[4:].isdigit():
            normalized.append(raw)
    return tuple(dict.fromkeys(normalized))
