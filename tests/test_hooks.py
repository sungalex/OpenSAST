"""확장 훅 emit() 동작 검증."""

from __future__ import annotations

from opensast.hooks import emit, hook_registry


class _CollectorHook:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    def pre_scan(self, scan_id, target):  # noqa: ARG002
        self.calls.append(("pre_scan", (scan_id,)))

    def post_scan(self, scan_id, result):  # noqa: ARG002
        self.calls.append(("post_scan", (scan_id,)))

    def on_status_change(self, finding, old, new):  # noqa: ARG002
        self.calls.append(("on_status_change", (old, new)))


class _BrokenHook:
    def pre_scan(self, *args, **kwargs):
        raise RuntimeError("boom")


def test_emit_calls_registered_hook() -> None:
    hook = _CollectorHook()
    hook_registry.register("collector-test", hook, replace=True)
    errors = emit("pre_scan", "sid-1", None)
    assert errors == []
    assert ("pre_scan", ("sid-1",)) in hook.calls
    hook_registry.unregister("collector-test")


def test_emit_swallows_errors() -> None:
    hook_registry.register("broken-test", _BrokenHook(), replace=True)
    errors = emit("pre_scan", "sid-1", None)
    assert len(errors) >= 1
    assert any(isinstance(e, RuntimeError) for e in errors)
    hook_registry.unregister("broken-test")


def test_emit_ignores_missing_method() -> None:
    class NoImpl:
        pass

    hook_registry.register("no-impl-test", NoImpl(), replace=True)
    # pre_scan 미구현이므로 오류 없이 통과
    errors = emit("pre_scan", "sid", None)
    assert errors == []
    hook_registry.unregister("no-impl-test")
