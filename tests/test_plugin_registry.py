"""플러그인 레지스트리 동작 검증."""

from __future__ import annotations

import pytest

from opensast.plugins import Registry, engine_registry, llm_registry, reference_registry


def test_builtin_engines_registered() -> None:
    names = engine_registry.names()
    for expected in ("opengrep", "bandit", "eslint", "gosec", "spotbugs", "codeql"):
        assert expected in names


def test_builtin_llm_providers_registered() -> None:
    assert "ollama" in llm_registry.names()
    assert "anthropic" in llm_registry.names()
    assert "noop" in llm_registry.names()


def test_registry_normalizes_names() -> None:
    r: Registry = Registry("test")
    r.register("MyPlugin", object)
    assert "myplugin" in r
    assert "myplugin" in r.names()


def test_registry_does_not_replace_unless_forced() -> None:
    r: Registry = Registry("test")
    r.register("x", "first")  # type: ignore[arg-type]
    r.register("x", "second", priority=200)  # type: ignore[arg-type]
    # 기존 등록이 낮은 priority 로 유지되어야 함
    assert r.get("x").factory == "first"

    r.register("x", "third", priority=10)  # type: ignore[arg-type]
    assert r.get("x").factory == "third"


def test_registry_get_raises_for_unknown() -> None:
    r: Registry = Registry("test")
    with pytest.raises(Exception):
        r.get("nonexistent")


def test_registry_disabled_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISAST_PLUGINS_DISABLED", "foo,bar")
    from opensast.plugins.registry import _disabled_plugins

    assert _disabled_plugins() == {"foo", "bar"}
