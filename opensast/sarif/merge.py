"""다중 엔진 Finding 병합·중복 제거."""

from __future__ import annotations

from collections import defaultdict

from opensast.models import Finding


def merge_findings(
    groups: list[list[Finding]], *, dedupe_same_location: bool = True
) -> list[Finding]:
    """여러 엔진에서 생성된 Finding 리스트를 합치고 중복을 제거한다.

    중복 기준:
      * `finding_id`가 동일한 경우 (엔진·규칙·파일·라인·MOIS ID 일치)
      * `dedupe_same_location`이 True면 동일 파일/라인/CWE/규칙 조합도 중복으로 간주

    **규칙 ID 를 키에 포함하는 이유 (M-1)**: 예전 키는 `(파일, 라인, CWE)` 였는데,
    CWE 매핑이 없는 Finding 들은 CWE 튜플이 모두 비어 있어 같은 줄의 서로 다른
    규칙 탐지가 하나로 붕괴했다. LLM 단계에서는 "원본 제거 금지" 를 강제하면서
    병합 단계에서 조용히 버리는 것은 행안부 대응 관점에서 감사 리스크다.
    CWE 가 없는 경우에는 규칙 ID 로 구분해 서로 다른 탐지를 보존한다.
    """

    flat: list[Finding] = [f for group in groups for f in group]
    by_id: dict[str, Finding] = {}
    for f in flat:
        by_id[f.finding_id] = f
    if not dedupe_same_location:
        return list(by_id.values())

    bucket: dict[tuple[str, int, tuple[str, ...], str], Finding] = {}
    for f in by_id.values():
        cwe_key = tuple(sorted(f.cwe_ids))
        # CWE 로 동치성을 판단할 수 없으면 규칙 ID 로 대체한다.
        rule_key = "" if cwe_key else f.rule_id
        key = (
            f.location.file_path,
            f.location.start_line,
            cwe_key,
            rule_key,
        )
        existing = bucket.get(key)
        if existing is None or _prefers(f, existing):
            bucket[key] = f
    return list(bucket.values())


_ENGINE_PRIORITY = {
    "codeql": 10,
    "spotbugs": 9,
    "opengrep": 8,
    "semgrep": 8,
    "bandit": 6,
    "gosec": 6,
    "eslint": 5,
}


_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _prefers(candidate: Finding, existing: Finding) -> bool:
    c_rank = _ENGINE_PRIORITY.get(candidate.engine.lower(), 0)
    e_rank = _ENGINE_PRIORITY.get(existing.engine.lower(), 0)
    if c_rank != e_rank:
        return c_rank > e_rank
    c_sev = _SEVERITY_RANK.get(candidate.severity.value, 0)
    e_sev = _SEVERITY_RANK.get(existing.severity.value, 0)
    return c_sev > e_sev


def coverage_by_mois(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.mois_id:
            out[f.mois_id] += 1
    return dict(out)


def coverage_by_engine(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for f in findings:
        out[f.engine] += 1
    return dict(out)
