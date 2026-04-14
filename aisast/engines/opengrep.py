"""Opengrep (Semgrep CE 호환) 엔진 어댑터.

aiSAST는 1차 Pass 주력 엔진으로 Opengrep/Semgrep을 사용한다. 양쪽 CLI가 SARIF
출력을 지원하므로 같은 어댑터가 둘 다 처리한다.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from aisast.engines.base import Engine, EngineResult, EngineUnavailable
from aisast.models import ScanTarget
from aisast.sarif.normalize import findings_from_sarif
from aisast.sarif.parser import parse_sarif_dict
from aisast.utils.logging import get_logger
from aisast.utils.subprocess import BinaryNotFound, run_capture

log = get_logger(__name__)


class OpengrepEngine(Engine):
    name = "opengrep"
    supported_languages = ("java", "python", "javascript", "typescript", "go", "php", "ruby")

    def run(self, target: ScanTarget) -> EngineResult:
        cfg_dir = self.settings.rules_dir / "opengrep"
        binary = self.settings.opengrep_bin
        if not cfg_dir.exists():
            log.warning("opengrep rules directory missing: %s", cfg_dir)
        with tempfile.TemporaryDirectory(prefix="aisast-opengrep-") as tmp:
            sarif_path = Path(tmp) / "output.sarif"
            cmd = [
                binary,
                "scan",
                "--config",
                str(cfg_dir),
                "--sarif",
                "--sarif-output",
                str(sarif_path),
                "--quiet",
                "--error",
                str(target.root),
            ]
            start = time.time()
            try:
                result = run_capture(cmd, timeout=900)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"opengrep binary not found: {exc}") from exc
            duration = time.time() - start
            # semgrep returns non-zero when findings exist; that is not a failure.
            if not sarif_path.exists():
                log.warning(
                    "opengrep finished with code %s but no SARIF produced", result.returncode
                )
                return EngineResult(
                    engine=self.name,
                    findings=[],
                    duration_seconds=duration,
                    returncode=result.returncode,
                    stdout_tail=self._tail(result.stdout),
                    stderr_tail=self._tail(result.stderr),
                )
            raw = json.loads(sarif_path.read_text(encoding="utf-8"))
            doc = parse_sarif_dict(raw)
            findings = findings_from_sarif(doc, engine=self.name)
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=result.returncode,
                stdout_tail=self._tail(result.stdout),
                stderr_tail=self._tail(result.stderr),
                metadata={"rules_dir": str(cfg_dir)},
            )
