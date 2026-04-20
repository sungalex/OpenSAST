"""aiSAST 플러그인 시스템.

엔진·LLM·리포트·레퍼런스·훅 을 동일한 메커니즘으로 관리해 외부 패키지가
코어 수정 없이 aiSAST 를 확장할 수 있게 한다.

두 가지 등록 경로:

1. **Entry Points** — 외부 패키지가 `pyproject.toml` 에 선언
   ```toml
   [project.entry-points."opensast.engines"]
   mysonar = "my_plugin:MySonarEngine"
   ```
2. **런타임 등록** — 코드에서 직접
   ```python
   from opensast.plugins import engine_registry
   engine_registry.register("mysonar", MySonarEngine)
   ```

시작 시 `discover_all()` 이 `OPENSAST_PLUGINS_DISABLED` 환경변수 화이트리스트를
제외하고 모든 entry_points 를 자동 발견한다.
"""

from opensast.plugins.registry import (
    Plugin,
    PluginError,
    Registry,
    discover_all,
    engine_registry,
    hook_registry,
    llm_registry,
    reference_registry,
    report_registry,
)

__all__ = [
    "Plugin",
    "PluginError",
    "Registry",
    "discover_all",
    "engine_registry",
    "hook_registry",
    "llm_registry",
    "reference_registry",
    "report_registry",
]
