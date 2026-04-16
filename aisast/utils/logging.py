"""로깅 — Rich(console) / JSON(cloud) 이중 모드."""

from __future__ import annotations

import logging
import os

_CONFIGURED = False


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    level = os.environ.get("AISAST_LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("AISAST_LOG_FORMAT", "console").lower()

    if fmt == "json":
        from pythonjsonlogger.json import JsonFormatter
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter(
            fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level"},
        ))
    else:
        from rich.logging import RichHandler
        handler = RichHandler(rich_tracebacks=True, show_path=False)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure_root()
    return logging.getLogger(name)
