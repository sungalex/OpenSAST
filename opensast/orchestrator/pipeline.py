"""2-Pass 분석 파이프라인.

1차 Pass: Opengrep/Bandit/ESLint/gosec — 고속 패턴 매칭
2차 Pass: CodeQL/SpotBugs — 심층 데이터플로우 분석
3단계: LLM Triage — 오탐 필터링 및 조치방안 생성

엔진 바이너리가 설치되지 않은 경우 해당 엔진은 경고 후 생략하며, 파이프라인은
설치된 엔진만으로도 정상 동작하도록 설계한다.

엔진 사이에는 의존성이 없으므로 한 Pass 안의 엔진들은 **동시에** 실행한다
(`settings.engine_max_concurrency`, 1 이면 순차). 예전에는 for 루프로 직렬
실행해 "다중 엔진 오케스트레이터" 라는 이름값을 못 했다.
"""

from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from opensast.config import Settings, get_settings
from opensast.engines import EngineUnavailable, UnknownEngine, build_engine
from opensast.engines.registry import FIRST_PASS_ENGINES, SECOND_PASS_ENGINES
from opensast.hooks import emit as emit_hook
from opensast.llm.triage import Triager
from opensast.models import Finding, ScanResult, ScanTarget
from opensast.sarif.merge import coverage_by_engine, coverage_by_mois, merge_findings
from opensast.utils.logging import get_logger

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
        notes: list[str] = []

        # 확장 훅: 스캔 시작 — 커스텀 감사/알림 발행 가능
        for err in emit_hook("pre_scan", scan_id, target):
            log.warning("pre_scan hook error: %s", err)

        first_engines = options.engines or FIRST_PASS_ENGINES
        first_pass_findings = self._run_pass(target, tuple(first_engines), "1st")

        second_pass_findings: list[list[Finding]] = []
        if options.enable_second_pass:
            second_engines = self._resolve_second_pass(options, notes)
            if second_engines:
                second_pass_findings = self._run_pass(target, second_engines, "2nd")

        merged = merge_findings(first_pass_findings + second_pass_findings)
        log.info(
            "merged %d findings from %d engine runs in %.2fs",
            len(merged),
            len(first_pass_findings) + len(second_pass_findings),
            time.time() - t0,
        )

        if options.enable_triage and merged:
            try:
                triager = Triager(settings=self.settings)
                triager.triage(merged, source_root=root)
                notes.extend(triager.last_report.notes)
            except Exception as exc:  # pragma: no cover - defensive guard
                log.warning("triage pipeline failed: %s", exc)
                notes.append(f"triage 실패: {exc}")

        finished_at = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=scan_id,
            target_root=str(root),
            started_at=started_at,
            finished_at=finished_at,
            findings=merged,
            engine_stats=coverage_by_engine(merged),
            mois_coverage=coverage_by_mois(merged),
            notes=notes,
        )

        # 확장 훅: 스캔 완료
        for err in emit_hook("post_scan", scan_id, result):
            log.warning("post_scan hook error: %s", err)

        return result

    # ---- 내부 ------------------------------------------------------------
    def _resolve_second_pass(
        self, options: ScanOptions, notes: list[str]
    ) -> tuple[str, ...]:
        """2차 Pass 대상 엔진 결정.

        사용자가 엔진 목록을 지정하면 그중 2차 Pass 엔진만 남는데, 결과가 빈
        목록이면 **조용히** 심층 분석이 생략된다 (O1). 그 경우 경고 로그와
        결과 노트를 남겨 사용자가 오해하지 않도록 한다.
        """

        if not options.engines:
            return SECOND_PASS_ENGINES
        selected = tuple(e for e in options.engines if e in SECOND_PASS_ENGINES)
        if not selected:
            msg = (
                "2차 Pass 가 생략되었습니다 — 지정한 엔진 "
                f"{list(options.engines)} 에 심층 분석 엔진"
                f"({', '.join(SECOND_PASS_ENGINES)})이 없습니다"
            )
            log.warning(msg)
            notes.append(msg)
        return selected

    def _run_pass(
        self,
        target: ScanTarget,
        engine_names: tuple[str, ...],
        label: str,
    ) -> list[list[Finding]]:
        engines = []
        for name in engine_names:
            try:
                engines.append((name, build_engine(name, settings=self.settings)))
            except UnknownEngine:
                log.warning("[%s pass] unknown engine: %s", label, name)
            except Exception as exc:  # noqa: BLE001 - 엔진 생성 실패는 격리
                log.warning("[%s pass] failed to build %s: %s", label, name, exc)
        if not engines:
            return []

        max_workers = max(1, int(self.settings.engine_max_concurrency))
        if max_workers == 1 or len(engines) == 1:
            outcomes = [
                self._run_one(name, engine, target, label) for name, engine in engines
            ]
        else:
            with ThreadPoolExecutor(
                max_workers=min(max_workers, len(engines)),
                thread_name_prefix=f"engine-{label}",
            ) as pool:
                outcomes = list(
                    pool.map(
                        lambda item: self._run_one(item[0], item[1], target, label),
                        engines,
                    )
                )
        return [findings for findings in outcomes if findings is not None]

    def _run_one(
        self, name: str, engine, target: ScanTarget, label: str
    ) -> list[Finding] | None:
        """엔진 하나를 실행한다. 실패는 격리하고 None 을 반환한다."""

        try:
            result = engine.run(target)
        except EngineUnavailable as exc:
            log.info("[%s pass] skipped %s: %s", label, name, exc)
            return None
        except Exception as exc:  # noqa: BLE001 - 한 엔진 실패가 스캔을 죽이지 않는다
            log.exception("[%s pass] %s crashed: %s", label, name, exc)
            return None
        log.info(
            "[%s pass] %s produced %d findings in %.2fs",
            label,
            name,
            len(result.findings),
            result.duration_seconds,
        )
        return result.findings


def run_scan(
    root: Path,
    *,
    options: ScanOptions | None = None,
    settings: Settings | None = None,
) -> ScanResult:
    return ScanPipeline(settings=settings).scan(root, options=options)
