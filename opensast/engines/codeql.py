"""CodeQL 어댑터 (2차 Pass 심층 분석).

CodeQL은 database create + database analyze 2단계로 동작하므로 본 어댑터도
해당 워크플로를 자동화한다. 쿼리팩은 공식 `codeql/java-queries` 등 표준 팩을
우선 사용하고, 프로젝트 `rules/codeql/<lang>/` 경로에 사용자 쿼리가 존재하면
추가로 포함한다.
"""

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

_LANG_TO_PACK = {
    "java": "codeql/java-queries",
    "kotlin": "codeql/java-queries",
    "python": "codeql/python-queries",
    "javascript": "codeql/javascript-queries",
    "typescript": "codeql/javascript-queries",
    "go": "codeql/go-queries",
    "cpp": "codeql/cpp-queries",
    "c": "codeql/cpp-queries",
}


class CodeqlEngine(Engine):
    name = "codeql"
    supported_languages = tuple(_LANG_TO_PACK.keys())

    def run(self, target: ScanTarget) -> EngineResult:
        language = target.language_hint or self._guess_language(target.root)
        if language is None:
            log.info("codeql: language could not be determined; skipping")
            return EngineResult(engine=self.name, findings=[])
        pack = _LANG_TO_PACK.get(language)
        if pack is None:
            return EngineResult(engine=self.name, findings=[])
        with tempfile.TemporaryDirectory(prefix="opensast-codeql-") as tmp:
            db_dir = Path(tmp) / "db"
            sarif_path = Path(tmp) / "codeql.sarif"
            create_cmd = [
                self.settings.codeql_bin,
                "database",
                "create",
                str(db_dir),
                f"--language={language}",
                f"--source-root={target.root}",
                "--overwrite",
            ]
            start = time.time()
            try:
                create = run_capture(create_cmd, timeout=3600)
                if create.returncode != 0:
                    return EngineResult(
                        engine=self.name,
                        findings=[],
                        duration_seconds=time.time() - start,
                        returncode=create.returncode,
                        stdout_tail=self._tail(create.stdout),
                        stderr_tail=self._tail(create.stderr),
                    )
                analyze_cmd = [
                    self.settings.codeql_bin,
                    "database",
                    "analyze",
                    str(db_dir),
                    pack,
                    "--format=sarifv2.1.0",
                    f"--output={sarif_path}",
                    "--download",
                ]
                custom = self.settings.rules_dir / "codeql" / language
                if custom.exists():
                    analyze_cmd.append(str(custom))
                analyze = run_capture(analyze_cmd, timeout=3600)
            except BinaryNotFound as exc:
                raise EngineUnavailable(f"codeql not found: {exc}") from exc
            duration = time.time() - start
            findings = []
            if sarif_path.exists():
                raw = json.loads(sarif_path.read_text(encoding="utf-8"))
                doc = parse_sarif_dict(raw)
                findings = findings_from_sarif(
                    doc, engine=self.name, language=language
                )
            return EngineResult(
                engine=self.name,
                findings=findings,
                duration_seconds=duration,
                returncode=analyze.returncode,
                stdout_tail=self._tail(analyze.stdout),
                stderr_tail=self._tail(analyze.stderr),
                metadata={"language": language, "pack": pack},
            )

    @staticmethod
    def _guess_language(root: Path) -> str | None:
        signatures: list[tuple[str, tuple[str, ...]]] = [
            ("java", ("pom.xml", "build.gradle", "build.gradle.kts")),
            ("python", ("pyproject.toml", "requirements.txt", "setup.py")),
            ("javascript", ("package.json",)),
            ("go", ("go.mod",)),
            ("cpp", ("CMakeLists.txt",)),
        ]
        for lang, files in signatures:
            for name in files:
                if (root / name).exists():
                    return lang
        return None
