"""gosec (Go 언어) 어댑터."""

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


class GosecEngine(Engine):
    name = "gosec"
    supported_languages = ("go",)

    def run(self, target: ScanTarget) -> EngineResult:
        with tempfile.TemporaryDirectory(prefix="opensast-gosec-") as tmp:
            out_path = Path(tmp) / "gosec.sarif"
            cmd = [
                self.settings.gosec_bin,
                "-fmt=sarif",
                f"-out={out_path}",
                "-quiet",
                "./...",
            ]
            start = time.time()
            try:
                result = run_capture(cmd, cwd=target.root, timeout=900)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"gosec not found: {exc}") from exc
            duration = time.time() - start
            findings = []
            if out_path.exists():
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                doc = parse_sarif_dict(raw)
                findings = findings_from_sarif(doc, engine=self.name, language="go")
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=result.returncode,
                stdout_tail=self._tail(result.stdout),
                stderr_tail=self._tail(result.stderr),
            )
