"""엔진 레지스트리 — 플러그인 시스템 위에 얹은 편의 레이어.

내장 엔진을 `aisast.plugins.engine_registry` 에 등록하고, 조회·가용성 점검을
위한 기존 API 를 보존한다. 외부 패키지가 entry_points 로 추가한 엔진도 동일
경로로 조회된다.
"""

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
from aisast.plugins.registry import engine_registry

# ---------------------------------------------------------------------------
# 내장 엔진을 플러그인 레지스트리에 등록 (priority=100 = 내장 기본값)
# ---------------------------------------------------------------------------
_BUILTIN: dict[str, type[Engine]] = {
    "opengrep": OpengrepEngine,
    "bandit": BanditEngine,
    "eslint": EslintEngine,
    "gosec": GosecEngine,
    "spotbugs": SpotbugsEngine,
    "codeql": CodeqlEngine,
}
for _name, _cls in _BUILTIN.items():
    engine_registry.register(_name, _cls, source="builtin", priority=50)

FIRST_PASS_ENGINES: tuple[str, ...] = ("opengrep", "bandit", "eslint", "gosec")
SECOND_PASS_ENGINES: tuple[str, ...] = ("codeql", "spotbugs")


# 하위 호환 — 기존 코드가 ENGINE_CLASSES 를 참조
ENGINE_CLASSES: dict[str, type[Engine]] = _BUILTIN


@dataclass
class EngineAvailability:
    name: str
    binary: str
    available: bool


def build_engine(name: str, settings: Settings | None = None) -> Engine:
    """플러그인 레지스트리에서 엔진 인스턴스 생성."""

    try:
        plugin = engine_registry.get(name)
    except KeyError as exc:
        raise KeyError(f"unknown engine: {name}") from exc
    return plugin.factory(settings=settings)


def available_engines(settings: Settings | None = None) -> list[EngineAvailability]:
    """설치된 엔진 바이너리 상태 조회.

    내장 6개 엔진 외에 플러그인이 엔진을 추가했더라도, 바이너리 매핑은 설정에
    정의된 것만 반환한다 (외부 엔진은 자체 가용성 확인이 필요함).
    """

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
