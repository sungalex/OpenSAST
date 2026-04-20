"""엔진 공통 인터페이스.

각 엔진은 `run(target)` 메서드로 Finding 리스트와 실행 메타데이터를 반환한다.
엔진 바이너리가 설치되어 있지 않으면 `EngineUnavailable`를 발생시켜 파이프라인이
건너뛸 수 있도록 한다.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path

from opensast.config import Settings, get_settings
from opensast.models import Finding, ScanTarget
from opensast.utils.logging import get_logger
from opensast.utils.subprocess import BinaryNotFound, CommandResult, run_capture

log = get_logger(__name__)


class EngineUnavailable(RuntimeError):
    """엔진 바이너리가 설치되어 있지 않거나 구성이 잘못된 경우."""


@dataclass
class EngineResult:
    engine: str
    findings: list[Finding]
    duration_seconds: float = 0.0
    returncode: int = 0
    stdout_tail: str = ""
    stderr_tail: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class Engine(abc.ABC):
    """SAST 엔진 공통 추상 클래스."""

    name: str = "base"
    supported_languages: tuple[str, ...] = ()

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @abc.abstractmethod
    def run(self, target: ScanTarget) -> EngineResult:
        """분석 대상 경로에 대해 엔진을 실행하고 결과를 반환."""

    def _run(self, cmd: list[str], *, cwd: Path | None = None, timeout: int = 900) -> CommandResult:
        try:
            return run_capture(cmd, cwd=cwd, timeout=timeout)
        except BinaryNotFound as exc:
            raise EngineUnavailable(f"{self.name}: binary not found ({exc})") from exc

    @staticmethod
    def _tail(text: str, limit: int = 2000) -> str:
        if len(text) <= limit:
            return text
        return text[-limit:]
