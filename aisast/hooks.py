"""스캔 수명주기 · 이슈 상태 확장 훅.

커스텀 감사·알림·Jira/Slack 연동 등을 코어 수정 없이 추가하기 위한 Protocol
기반 확장 포인트. 훅 구현체는 `aisast.plugins.hook_registry` 에 등록된다:

```python
from aisast.hooks import ScanHook, hook_registry

class MyHook(ScanHook):
    def post_scan(self, scan_id, result):
        notify_slack(scan_id, len(result.findings))

hook_registry.register("slack-notify", MyHook())
```

외부 패키지의 경우 `pyproject.toml` 에:

```toml
[project.entry-points."aisast.hooks"]
slack-notify = "my_plugin:MyHook"
```

훅에 정의되지 않은 콜백은 무시된다 (duck typing). 훅 내 예외는 격리되어
호출자에게 전파되지 않는다.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from aisast.db import models
from aisast.models import ScanResult, ScanTarget
from aisast.plugins.registry import hook_registry

__all__ = ["ScanHook", "hook_registry"]


@runtime_checkable
class ScanHook(Protocol):
    """스캔 수명주기 확장 인터페이스.

    모든 메서드는 선택사항. 구현체는 필요한 것만 정의한다.
    """

    def pre_scan(self, scan_id: str, target: ScanTarget) -> None: ...

    def post_scan(self, scan_id: str, result: ScanResult) -> None: ...

    def pre_persist(self, scan_id: str, result: ScanResult) -> None: ...

    def post_persist(self, scan_id: str, scan: models.Scan) -> None: ...

    def on_status_change(
        self, finding: models.Finding, old_status: str, new_status: str
    ) -> None: ...


def emit(event: str, *args, **kwargs) -> list[Exception]:
    """모든 등록 훅의 해당 이벤트 메서드를 안전하게 호출.

    Returns: 실패한 훅이 던진 예외 목록 (호출자는 감사 로그에 기록).
    """

    errors: list[Exception] = []
    for plugin in hook_registry.all():
        handler = getattr(plugin.factory, event, None)
        if not callable(handler):
            continue
        try:
            handler(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    return errors
