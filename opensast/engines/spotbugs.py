"""SpotBugs + Find Security Bugs 어댑터 (Java 2차 Pass)."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from opensast.engines.base import Engine, EngineResult, EngineUnavailable
from opensast.models import ScanTarget
from opensast.sarif.normalize import findings_from_sarif
from opensast.sarif.parser import parse_sarif_dict
from opensast.utils.logging import get_logger
from opensast.utils.subprocess import BinaryNotFound, run_capture

log = get_logger(__name__)


class SpotbugsEngine(Engine):
    name = "spotbugs"
    supported_languages = ("java", "kotlin", "scala")

    def run(self, target: ScanTarget) -> EngineResult:
        class_dirs = self._collect_class_dirs(target.root)
        if not class_dirs:
            log.info("spotbugs: no compiled .class directories found; skipping")
            return EngineResult(engine=self.name, findings=[])
        with tempfile.TemporaryDirectory(prefix="opensast-spotbugs-") as tmp:
            out_path = Path(tmp) / "spotbugs.sarif"
            cmd = [
                self.settings.spotbugs_bin,
                "-textui",
                "-sarif",
                "-quiet",
                "-output",
                str(out_path),
                *[str(d) for d in class_dirs],
            ]
            start = time.time()
            try:
                result = run_capture(cmd, timeout=1800)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"spotbugs not found: {exc}") from exc
            duration = time.time() - start
            findings = []
            if out_path.exists():
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                doc = parse_sarif_dict(raw)
                findings = findings_from_sarif(doc, engine=self.name, language="java")
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=result.returncode,
                stdout_tail=self._tail(result.stdout),
                stderr_tail=self._tail(result.stderr),
                metadata={"class_dirs": ",".join(str(d) for d in class_dirs)},
            )

    @staticmethod
    def _collect_class_dirs(root: Path) -> list[Path]:
        candidates = {
            root / "build" / "classes",
            root / "target" / "classes",
            root / "out" / "production",
        }
        return sorted([c for c in candidates if c.exists()])
