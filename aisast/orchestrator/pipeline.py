"""2-Pass 분석 파이프라인.

1차 Pass: Opengrep/Bandit/ESLint/gosec — 고속 패턴 매칭
2차 Pass: CodeQL/SpotBugs — 심층 데이터플로우 분석
3단계: LLM Triage — 오탐 필터링 및 조치방안 생성

엔진 바이너리가 설치되지 않은 경우 해당 엔진은 경고 후 생략하며, 파이프라인은
설치된 엔진만으로도 정상 동작하도록 설계한다.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aisast.config import Settings, get_settings
from aisast.engines import EngineUnavailable, build_engine
from aisast.engines.registry import FIRST_PASS_ENGINES, SECOND_PASS_ENGINES
from aisast.hooks import emit as emit_hook
from aisast.llm.triage import Triager
from aisast.models import Finding, ScanResult, ScanTarget
from aisast.sarif.merge import coverage_by_engine, coverage_by_mois, merge_findings
from aisast.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class ScanOptions:
    enable_second_pass: bool = True
    enable_triage: bool = True
    engines: tuple[str, ...] = ()  # 빈 튜플이면 기본 엔진 세트 사용
    language_hint: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


class ScanPipeline:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def scan(
        self,
        root: Path,
        *,
        options: ScanOptions | None = None,
    ) -> ScanResult:
        options = options or ScanOptions()
        target = ScanTarget(root=root, language_hint=options.language_hint)
        scan_id = uuid.uuid4().hex[:12]
        started_at = datetime.now(timezone.utc)
        t0 = time.time()

        # 확장 훅: 스캔 시작 — 커스텀 감사/알림 발행 가능
        errors = emit_hook("pre_scan", scan_id, target)
        for err in errors:
            log.warning("pre_scan hook error: %s", err)

        first_pass_findings = self._run_pass(
            target, options.engines or FIRST_PASS_ENGINES, "1st"
        )

        second_pass_findings: list[list[Finding]] = []
        if options.enable_second_pass and not options.engines:
            second_pass_findings = self._run_pass(
                target, SECOND_PASS_ENGINES, "2nd"
            )

        merged = merge_findings(first_pass_findings + second_pass_findings)
        log.info("merged %d findings from %d engine runs", len(merged), len(first_pass_findings) + len(second_pass_findings))

        if options.enable_triage and merged:
            try:
                Triager(settings=self.settings).triage(merged, source_root=root)
            except Exception as exc:  # pragma: no cover - defensive guard
                log.warning("triage pipeline failed: %s", exc)

        finished_at = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=scan_id,
            target_root=str(root),
            started_at=started_at,
            finished_at=finished_at,
            findings=merged,
            engine_stats=coverage_by_engine(merged),
            mois_coverage=coverage_by_mois(merged),
        )

        # 확장 훅: 스캔 완료
        for err in emit_hook("post_scan", scan_id, result):
            log.warning("post_scan hook error: %s", err)

        return result

    def _run_pass(
        self,
        target: ScanTarget,
        engine_names: tuple[str, ...],
        label: str,
    ) -> list[list[Finding]]:
        groups: list[list[Finding]] = []
        for name in engine_names:
            try:
                engine = build_engine(name, settings=self.settings)
            except KeyError:
                log.warning("[%s pass] unknown engine: %s", label, name)
                continue
            try:
                result = engine.run(target)
            except EngineUnavailable as exc:
                log.info("[%s pass] skipped %s: %s", label, name, exc)
                continue
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("[%s pass] %s crashed: %s", label, name, exc)
                continue
            log.info(
                "[%s pass] %s produced %d findings in %.2fs",
                label,
                name,
                len(result.findings),
                result.duration_seconds,
            )
            groups.append(result.findings)
        return groups


def run_scan(
    root: Path,
    *,
    options: ScanOptions | None = None,
    settings: Settings | None = None,
) -> ScanResult:
    return ScanPipeline(settings=settings).scan(root, options=options)
