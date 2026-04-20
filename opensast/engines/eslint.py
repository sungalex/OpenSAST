"""ESLint (JavaScript/TypeScript 보안 플러그인) 어댑터."""

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


class EslintEngine(Engine):
    name = "eslint"
    supported_languages = ("javascript", "typescript")

    def run(self, target: ScanTarget) -> EngineResult:
        with tempfile.TemporaryDirectory(prefix="opensast-eslint-") as tmp:
            out_path = Path(tmp) / "eslint.sarif"
            cmd = [
                self.settings.eslint_bin,
                "--format",
                "@microsoft/eslint-formatter-sarif",
                "--output-file",
                str(out_path),
                "--ext",
                ".js,.jsx,.ts,.tsx",
                str(target.root),
            ]
            start = time.time()
            try:
                result = run_capture(cmd, timeout=900)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"eslint not found: {exc}") from exc
            duration = time.time() - start
            findings = []
            if out_path.exists():
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                doc = parse_sarif_dict(raw)
                findings = findings_from_sarif(
                    doc, engine=self.name, language="javascript"
                )
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=result.returncode,
                stdout_tail=self._tail(result.stdout),
                stderr_tail=self._tail(result.stderr),
            )
