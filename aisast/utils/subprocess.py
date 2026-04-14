"""하위 프로세스 실행 헬퍼.

엔진 어댑터가 엔진 바이너리를 호출할 때 사용한다. 바이너리가 PATH에 없으면
`BinaryNotFound`를 발생시켜 호출자가 우아하게 스킵할 수 있게 한다.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class BinaryNotFound(FileNotFoundError):
    """엔진 바이너리가 PATH에 존재하지 않을 때 발생."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_capture(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    check: bool = False,
) -> CommandResult:
    """주어진 명령을 실행하고 stdout/stderr를 캡처한다."""

    binary = cmd[0]
    if shutil.which(binary) is None:
        raise BinaryNotFound(binary)
    try:
        completed = subprocess.run(  # noqa: S603 - controlled inputs
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=check,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=124,
            stdout=exc.stdout.decode("utf-8", "replace") if exc.stdout else "",
            stderr=(exc.stderr.decode("utf-8", "replace") if exc.stderr else "")
            + f"\n[timeout after {timeout}s]",
        )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
