"""타입 제약형 플러그인 레지스트리.

설계 원칙:
- **ONE class, many categories**: 제네릭 `Registry[T]` 가 카테고리마다 인스턴스화된다.
- **멱등 등록**: 같은 이름을 두 번 등록하면 경고 후 기존 것을 유지 (우선순위 명시적).
- **지연 로드**: entry_points 는 `discover()` 호출 시점에 가져오며, 로드 실패는
  로그만 남기고 계속 진행 (하나의 플러그인이 깨져도 시스템 전체가 멈추지 않음).
- **비활성화 가능**: `OPENSAST_PLUGINS_DISABLED="name1,name2"` 로 선택적 차단.
"""

from __future__ import annotations

import importlib.metadata as im
import os
from dataclasses import dataclass, field
from typing import Callable, Generic, Iterator, TypeVar

from opensast.utils.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")


class PluginError(RuntimeError):
    """플러그인 로드·검증 실패."""


@dataclass
class Plugin(Generic[T]):
    """단일 등록 항목."""

    name: str
    factory: Callable[..., T] | type[T]
    source: str = "builtin"  # "builtin" | "entry_point" | "runtime"
    priority: int = 100  # 낮을수록 우선 (향후 충돌 해결에 사용)
    metadata: dict[str, str] = field(default_factory=dict)


class Registry(Generic[T]):
    """카테고리별 플러그인 저장소."""

    def __init__(self, group: str, *, description: str = "") -> None:
        self.group = group
        self.description = description
        self._items: dict[str, Plugin[T]] = {}
        self._discovered = False

    # ---- 등록 -----------------------------------------------------------
    def register(
        self,
        name: str,
        factory: Callable[..., T] | type[T],
        *,
        source: str = "runtime",
        priority: int = 100,
        metadata: dict[str, str] | None = None,
        replace: bool = False,
    ) -> None:
        name = self._normalize_name(name)
        if name in self._items and not replace:
            existing = self._items[name]
            if existing.priority <= priority:
                log.debug(
                    "[%s] plugin %r already registered from %s (priority %s) — "
                    "ignoring new from %s",
                    self.group,
                    name,
                    existing.source,
                    existing.priority,
                    source,
                )
                return
        self._items[name] = Plugin(
            name=name,
            factory=factory,
            source=source,
            priority=priority,
            metadata=metadata or {},
        )
        log.debug("[%s] registered %r from %s", self.group, name, source)

    def unregister(self, name: str) -> None:
        self._items.pop(self._normalize_name(name), None)

    def get(self, name: str) -> Plugin[T]:
        key = self._normalize_name(name)
        if key not in self._items:
            raise PluginError(
                f"{self.group}: plugin {name!r} not found. "
                f"Available: {sorted(self._items)}"
            )
        return self._items[key]

    def create(self, name: str, *args, **kwargs) -> T:
        plugin = self.get(name)
        return plugin.factory(*args, **kwargs)

    def all(self) -> list[Plugin[T]]:
        return list(self._items.values())

    def names(self) -> list[str]:
        return sorted(self._items)

    def __iter__(self) -> Iterator[Plugin[T]]:
        return iter(self._items.values())

    def __contains__(self, name: str) -> bool:
        return self._normalize_name(name) in self._items

    # ---- Entry Points 발견 ---------------------------------------------
    def discover(self, *, force: bool = False) -> list[str]:
        """entry_points 를 스캔해 플러그인 로드.

        Returns: 이번 호출에서 새로 등록된 플러그인 이름 목록.
        """

        if self._discovered and not force:
            return []
        self._discovered = True

        disabled = _disabled_plugins()
        loaded: list[str] = []
        try:
            eps = im.entry_points(group=self.group)
        except TypeError:  # Python 3.9 fallback
            eps = im.entry_points().get(self.group, [])  # type: ignore[union-attr]

        for ep in eps:
            if ep.name in disabled:
                log.info("[%s] skipping disabled plugin %r", self.group, ep.name)
                continue
            try:
                factory = ep.load()
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "[%s] failed to load plugin %r: %s", self.group, ep.name, exc
                )
                continue
            self.register(
                ep.name,
                factory,
                source="entry_point",
                metadata={"module": ep.value},
            )
            loaded.append(ep.name)
        return loaded

    # ---- 내부 -----------------------------------------------------------
    @staticmethod
    def _normalize_name(name: str) -> str:
        return name.strip().lower()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Registry(group={self.group!r}, items={self.names()})"


def _disabled_plugins() -> set[str]:
    raw = os.environ.get("OPENSAST_PLUGINS_DISABLED", "")
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


# ---------------------------------------------------------------------------
# 전역 레지스트리 인스턴스 (카테고리별 싱글톤)
# ---------------------------------------------------------------------------

engine_registry: Registry = Registry(
    "opensast.engines",
    description="SAST 분석 엔진 어댑터 (Engine 서브클래스)",
)
llm_registry: Registry = Registry(
    "opensast.llm",
    description="LLM 프로바이더 (LLMClient 서브클래스)",
)
report_registry: Registry = Registry(
    "opensast.reports",
    description="리포트 포맷 생성기",
)
reference_registry: Registry = Registry(
    "opensast.references",
    description="외부 보안 표준 레퍼런스 (OWASP/SANS/PCI 등)",
)
hook_registry: Registry = Registry(
    "opensast.hooks",
    description="스캔 수명주기 / 이슈 상태 훅",
)


def discover_all(*, force: bool = False) -> dict[str, list[str]]:
    """5개 레지스트리 모두에서 entry_points 발견을 수행."""

    return {
        r.group: r.discover(force=force)
        for r in (
            engine_registry,
            llm_registry,
            report_registry,
            reference_registry,
            hook_registry,
        )
    }
