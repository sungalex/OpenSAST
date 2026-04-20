"""Bandit (Python) 엔진 어댑터."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from opensast.engines.base import Engine, EngineResult, EngineUnavailable
from opensast.models import ScanTarget
from opensast.sarif.normalize import findings_from_sarif
from opensast.sarif.parser import parse_sarif_dict
from opensast.utils.subprocess import BinaryNotFound, run_capture


class BanditEngine(Engine):
    name = "bandit"
    supported_languages = ("python",)

    def run(self, target: ScanTarget) -> EngineResult:
        with tempfile.TemporaryDirectory(prefix="aisast-bandit-") as tmp:
            out_path = Path(tmp) / "bandit.sarif"
            cmd = [
                self.settings.bandit_bin,
                "-r",
                str(target.root),
                "-f",
                "sarif",
                "-o",
                str(out_path),
                "--quiet",
            ]
            start = time.time()
            try:
                result = run_capture(cmd, timeout=600)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"bandit not found: {exc}") from exc
            duration = time.time() - start
            findings = []
            if out_path.exists():
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                doc = parse_sarif_dict(raw)
                findings = findings_from_sarif(doc, engine=self.name, language="python")
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=result.returncode,
                stdout_tail=self._tail(result.stdout),
                stderr_tail=self._tail(result.stderr),
            )
