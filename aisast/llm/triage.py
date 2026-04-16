"""LLM 기반 오탐 필터링 파이프라인."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from aisast.config import Settings, get_settings
from aisast.llm.anthropic import AnthropicClient
from aisast.llm.base import LLMClient, LLMError
from aisast.llm.noop import NoopLLMClient
from aisast.llm.ollama import OllamaClient
from aisast.llm.prompts import SYSTEM_PROMPT, USER_TEMPLATE
from aisast.mois.catalog import get_item
from aisast.models import Finding, TriageResult
from aisast.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class TriageContext:
    code_context: str
    language: str


class Triager:
    """Finding 리스트에 LLM 판정을 덧붙이는 오탐 필터 파이프라인.

    LLM 결과는 **원본 Finding을 제거하지 않고** `triage` 필드에만 기록한다.
    이는 계획서 리스크 섹션의 'LLM은 필터링(제거)에만 사용, 원본 탐지 결과는
    항상 보존' 원칙을 강제한다.
    """

    def __init__(
        self,
        client: LLMClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or build_client(self.settings)

    def triage(
        self, findings: list[Finding], *, source_root: Path | None = None
    ) -> list[Finding]:
        default_fp = self.settings.llm_default_fp_probability
        for finding in findings:
            # 캐시 확인
            cache_key = self._cache_key(finding)
            cached = self._get_cached(cache_key)
            if cached is not None:
                finding.triage = cached
                continue
            try:
                ctx = self._collect_context(finding, source_root)
                system = SYSTEM_PROMPT
                mois = get_item(finding.mois_id) if finding.mois_id else None
                user = USER_TEMPLATE.format(
                    name_kr=mois.name_kr if mois else "미매핑",
                    cwe=",".join(finding.cwe_ids) or "N/A",
                    mois_id=finding.mois_id or "N/A",
                    file_path=finding.location.file_path,
                    start_line=finding.location.start_line,
                    engine=finding.engine,
                    rule_id=finding.rule_id,
                    message=finding.message,
                    language=ctx.language,
                    code_context=ctx.code_context,
                )
                response = self._complete_with_retry(system, user)
                result = self._parse_response(
                    response.text, response.model, default_fp=default_fp
                )
                finding.triage = result
                self._set_cached(cache_key, result)
            except LLMError as exc:
                log.warning("triage failed for %s: %s", finding.finding_id, exc)
                finding.triage = TriageResult(
                    verdict="needs_review",
                    fp_probability=default_fp,
                    rationale=f"LLM 호출 실패: {exc}",
                    model=self.client.name,
                )
        return findings

    def _complete_with_retry(self, system: str, user: str):
        """tenacity 기반 재시도로 LLM 호출."""
        from tenacity import (
            retry,
            retry_if_exception_type,
            stop_after_attempt,
            wait_exponential,
        )

        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type(LLMError),
            reraise=True,
        )
        def _call():
            return self.client.complete(system, user)

        return _call()

    @staticmethod
    def _cache_key(finding: Finding) -> str:
        raw = (
            f"{finding.rule_id}:{finding.location.file_path}"
            f":{finding.location.start_line}"
            f":{(finding.location.snippet or '')[:200]}"
        )
        return f"triage:{hashlib.sha256(raw.encode()).hexdigest()[:24]}"

    def _get_cached(self, key: str) -> TriageResult | None:
        """Redis에서 캐시된 triage 결과 조회."""
        try:
            import redis

            r = redis.from_url(self.settings.redis_url)
            data = r.get(key)
            if data is None:
                return None
            import json as _json

            payload = _json.loads(data)
            return TriageResult(
                verdict=payload["verdict"],
                fp_probability=payload["fp_probability"],
                rationale=payload.get("rationale", ""),
                recommended_fix=payload.get("recommended_fix"),
                patched_code=payload.get("patched_code"),
                model=payload.get("model", "cached"),
            )
        except Exception:
            return None

    def _set_cached(self, key: str, result: TriageResult) -> None:
        """Triage 결과를 Redis에 24h TTL로 캐시."""
        try:
            import redis
            import json as _json

            r = redis.from_url(self.settings.redis_url)
            r.setex(key, 86400, _json.dumps(result.as_dict()))
        except Exception:
            pass

    def _collect_context(
        self, finding: Finding, source_root: Path | None
    ) -> TriageContext:
        window = self.settings.llm_context_window_lines
        language = finding.language or _guess_language_from_path(
            finding.location.file_path
        )
        if source_root is None:
            return TriageContext(
                code_context=finding.location.snippet or "",
                language=language,
            )
        file_path = (source_root / finding.location.file_path).resolve()
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError):
            return TriageContext(
                code_context=finding.location.snippet or "",
                language=language,
            )
        lines = text.splitlines()
        start = max(finding.location.start_line - window - 1, 0)
        end = min(finding.location.start_line + window, len(lines))
        snippet = "\n".join(
            f"{i + 1:>5}: {line}" for i, line in enumerate(lines[start:end], start=start)
        )
        return TriageContext(code_context=snippet, language=language)

    @staticmethod
    def _parse_response(
        text: str, model: str, *, default_fp: int = 50
    ) -> TriageResult:
        payload = _extract_json_object(text)
        if payload is None:
            return TriageResult(
                verdict="needs_review",
                fp_probability=default_fp,
                rationale="LLM 응답 JSON 파싱 실패",
                model=model,
            )
        verdict = str(payload.get("verdict") or "needs_review")
        fp_raw = payload.get("fp_probability")
        if fp_raw is None:
            fp_prob = default_fp
        else:
            try:
                fp_prob = int(fp_raw)
            except (TypeError, ValueError):
                fp_prob = default_fp
        fp_prob = max(0, min(fp_prob, 100))
        return TriageResult(
            verdict=verdict,
            fp_probability=fp_prob,
            rationale=str(payload.get("rationale") or "").strip(),
            recommended_fix=payload.get("recommended_fix"),
            patched_code=payload.get("patched_code"),
            model=model,
        )


def build_client(settings: Settings | None = None) -> LLMClient:
    """플러그인 레지스트리에서 LLM 클라이언트를 생성한다.

    내장 프로바이더: `ollama`, `anthropic`, `noop`.
    외부 플러그인이 entry_points 로 등록한 프로바이더도 동일하게 조회된다.
    프로바이더 초기화가 실패하면 (`LLMError`) `noop` 으로 자동 폴백한다.
    """

    from aisast.plugins.registry import engine_registry  # noqa: F401
    from aisast.plugins.registry import llm_registry

    settings = settings or get_settings()
    provider = settings.llm_provider.lower()
    try:
        plugin = llm_registry.get(provider)
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM provider %r not found in registry: %s", provider, exc)
        plugin = llm_registry.get("noop")
    try:
        return plugin.factory(settings)
    except TypeError:
        # factory 가 인수를 받지 않는 경우 (예: NoopLLMClient)
        return plugin.factory()
    except LLMError as exc:
        log.warning("LLM provider %s unavailable: %s", provider, exc)
        return llm_registry.get("noop").factory()


_JSON_BLOCK_RE = re.compile(r"\{[\s\S]*\}")


def _extract_json_object(text: str) -> dict | None:
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


_EXT_MAP = {
    ".java": "java",
    ".kt": "kotlin",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".xml": "xml",
}


def _guess_language_from_path(file_path: str) -> str:
    for ext, lang in _EXT_MAP.items():
        if file_path.endswith(ext):
            return lang
    return "text"
