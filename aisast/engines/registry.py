"""엔진 레지스트리 & 가용성 점검."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from aisast.config import Settings, get_settings
from aisast.engines.bandit import BanditEngine
from aisast.engines.base import Engine
from aisast.engines.codeql import CodeqlEngine
from aisast.engines.eslint import EslintEngine
from aisast.engines.gosec import GosecEngine
from aisast.engines.opengrep import OpengrepEngine
from aisast.engines.spotbugs import SpotbugsEngine

ENGINE_CLASSES: dict[str, type[Engine]] = {
    "opengrep": OpengrepEngine,
    "bandit": BanditEngine,
    "eslint": EslintEngine,
    "gosec": GosecEngine,
    "spotbugs": SpotbugsEngine,
    "codeql": CodeqlEngine,
}

FIRST_PASS_ENGINES: tuple[str, ...] = ("opengrep", "bandit", "eslint", "gosec")
SECOND_PASS_ENGINES: tuple[str, ...] = ("codeql", "spotbugs")


@dataclass
class EngineAvailability:
    name: str
    binary: str
    available: bool


def build_engine(name: str, settings: Settings | None = None) -> Engine:
    cls = ENGINE_CLASSES.get(name)
    if cls is None:
        raise KeyError(f"unknown engine: {name}")
    return cls(settings=settings)


def available_engines(settings: Settings | None = None) -> list[EngineAvailability]:
    settings = settings or get_settings()
    binary_map = {
        "opengrep": settings.opengrep_bin,
        "bandit": settings.bandit_bin,
        "eslint": settings.eslint_bin,
        "gosec": settings.gosec_bin,
        "spotbugs": settings.spotbugs_bin,
        "codeql": settings.codeql_bin,
    }
    out: list[EngineAvailability] = []
    for name, binary in binary_map.items():
        out.append(
            EngineAvailability(
                name=name,
                binary=binary,
                available=shutil.which(binary) is not None,
            )
        )
    return out
