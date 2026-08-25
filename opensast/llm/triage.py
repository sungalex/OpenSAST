"""LLM 기반 오탐 필터링 파이프라인.

**설계 원칙 (ADR-0008)**

1. **원본 보존** — LLM 결과는 `Finding.triage` 필드에만 기록하며 Finding 을
   제거하지 않는다. 행안부 지침 대응의 핵심 제약이다.
2. **동시 실행** — Finding 당 LLM 호출 1회를 직렬로 돌리면 1,000건에서
   soft time limit(기본 1,800초)을 반드시 넘긴다. `llm_max_concurrency` 만큼
   동시에 호출한다.
3. **조용한 실패 금지** — Redis 캐시 연결 실패는 예전에 `except: pass` 로
   삼켜져, 배포에서 캐시가 완전히 죽어 있어도 아무도 몰랐다. 이제 최초 1회
   WARNING 을 남기고 그 실행 동안 캐시를 비활성으로 표시한다.
4. **축소 사실 기록** — 상한(`triage_max_findings`)에 걸려 잘린 건수는
   `TriageReport.truncated` 로 보고되어 스캔 결과 노트에 실린다.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from opensast.config import Settings, get_settings
from opensast.llm.anthropic import AnthropicClient
from opensast.llm.base import LLMClient, LLMError
from opensast.llm.noop import NoopLLMClient
from opensast.llm.ollama import OllamaClient
from opensast.llm.prompts import SYSTEM_PROMPT, USER_TEMPLATE
from opensast.mois.catalog import get_item
from opensast.models import Finding, TriageResult
from opensast.utils.logging import get_logger

log = get_logger(__name__)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class TriageContext:
    code_context: str
    language: str


@dataclass
class TriageReport:
    """한 번의 triage 실행 결과 요약."""

    total: int = 0
    triaged: int = 0
    cached: int = 0
    failed: int = 0
    truncated: int = 0
    cache_enabled: bool = True
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Redis 커넥션 풀 — Finding 마다 새 커넥션을 만들던 문제를 제거한다
# ---------------------------------------------------------------------------


@lru_cache(maxsize=8)
def _redis_client(url: str):
    """URL 당 하나의 클라이언트(내부 커넥션 풀)를 재사용한다."""

    import redis

    return redis.from_url(
        url,
        socket_connect_timeout=2,
        socket_timeout=2,
        health_check_interval=30,
    )


def reset_redis_cache() -> None:
    """테스트에서 커넥션 풀을 초기화한다."""

    _redis_client.cache_clear()


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
        self.last_report = TriageReport()
        self._cache_enabled = self.settings.triage_cache_ttl_seconds > 0
        self._cache_warned = False
        self._lock = threading.Lock()

    # ---- 공개 API --------------------------------------------------------
    def triage(
        self, findings: list[Finding], *, source_root: Path | None = None
    ) -> list[Finding]:
        report = TriageReport(total=len(findings), cache_enabled=self._cache_enabled)
        targets = self._select_targets(findings, report)
        if not targets:
            self.last_report = report
            return findings

        workers = max(1, int(self.settings.llm_max_concurrency))
        if workers == 1 or len(targets) == 1:
            for finding in targets:
                self._triage_one(finding, source_root, report)
        else:
            with ThreadPoolExecutor(
                max_workers=min(workers, len(targets)),
                thread_name_prefix="triage",
            ) as pool:
                list(
                    pool.map(
                        lambda f: self._triage_one(f, source_root, report),
                        targets,
                    )
                )

        report.cache_enabled = self._cache_enabled
        if report.failed:
            log.warning(
                "triage: %d/%d findings 판정 실패 (needs_review 로 표시됨)",
                report.failed,
                report.total,
            )
        self.last_report = report
        return findings

    # ---- 내부 ------------------------------------------------------------
    def _select_targets(
        self, findings: list[Finding], report: TriageReport
    ) -> list[Finding]:
        """상한을 적용하되, 잘린 사실을 반드시 기록한다."""

        cap = int(self.settings.triage_max_findings or 0)
        if cap <= 0 or len(findings) <= cap:
            return list(findings)
        ordered = sorted(
            findings,
            key=lambda f: _SEVERITY_RANK.get(getattr(f.severity, "value", ""), 9),
        )
        report.truncated = len(findings) - cap
        msg = (
            f"triage 상한 {cap} 초과 — severity 순으로 {cap}건만 판정하고 "
            f"{report.truncated}건은 미판정으로 남깁니다"
        )
        report.notes.append(msg)
        log.warning(msg)
        return ordered[:cap]

    def _triage_one(
        self, finding: Finding, source_root: Path | None, report: TriageReport
    ) -> None:
        cache_key = self._cache_key(finding)
        cached = self._get_cached(cache_key)
        if cached is not None:
            finding.triage = cached
            with self._lock:
                report.cached += 1
            return

        default_fp = self.settings.llm_default_fp_probability
        try:
            ctx = self._collect_context(finding, source_root)
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
            response = self._complete_with_retry(SYSTEM_PROMPT, user)
            result = self._parse_response(
                response.text, response.model, default_fp=default_fp
            )
            finding.triage = result
            self._set_cached(cache_key, result)
            with self._lock:
                report.triaged += 1
        except Exception as exc:  # noqa: BLE001
            # LLMError 만 잡던 예전 구현은 그 외 예외 하나가 나머지 Finding 의
            # triage 를 통째로 날렸다. 실패는 Finding 단위로 격리한다.
            log.warning(
                "triage failed for %s (%s): %s",
                finding.finding_id,
                type(exc).__name__,
                exc,
            )
            finding.triage = TriageResult(
                verdict="needs_review",
                fp_probability=default_fp,
                rationale=f"LLM 판정 실패({type(exc).__name__}): {exc}",
                model=self.client.name,
            )
            with self._lock:
                report.failed += 1

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

    # ---- 캐시 ------------------------------------------------------------
    def _disable_cache(self, exc: Exception) -> None:
        """캐시 실패를 **한 번은 반드시 보고**하고 이후 시도를 멈춘다."""

        with self._lock:
            if self._cache_warned:
                return
            self._cache_warned = True
            self._cache_enabled = False
        log.warning(
            "triage 캐시 비활성화 — Redis(%s) 접근 실패: %s. "
            "워커 컨테이너에 OPENSAST_REDIS_URL 이 주입되어 있는지 확인하세요.",
            self.settings.redis_url,
            exc,
        )

    def _get_cached(self, key: str) -> TriageResult | None:
        if not self._cache_enabled:
            return None
        try:
            data = _redis_client(self.settings.redis_url).get(key)
        except Exception as exc:  # noqa: BLE001
            self._disable_cache(exc)
            return None
        if data is None:
            return None
        try:
            payload = json.loads(data)
            return TriageResult(
                verdict=payload["verdict"],
                fp_probability=payload["fp_probability"],
                rationale=payload.get("rationale", ""),
                recommended_fix=payload.get("recommended_fix"),
                patched_code=payload.get("patched_code"),
                model=payload.get("model", "cached"),
            )
        except (ValueError, KeyError, TypeError) as exc:
            log.debug("triage 캐시 항목 파손 (%s): %s", key, exc)
            return None

    def _set_cached(self, key: str, result: TriageResult) -> None:
        if not self._cache_enabled:
            return
        ttl = int(self.settings.triage_cache_ttl_seconds)
        try:
            _redis_client(self.settings.redis_url).set(
                key, json.dumps(result.as_dict()), ex=ttl
            )
        except Exception as exc:  # noqa: BLE001
            self._disable_cache(exc)

    # ---- 컨텍스트 --------------------------------------------------------
    def _collect_context(
        self, finding: Finding, source_root: Path | None
    ) -> TriageContext:
        window = self.settings.llm_context_window_lines
        language = finding.language or _guess_language_from_path(
            finding.location.file_path
        )
        fallback = TriageContext(
            code_context=finding.location.snippet or "", language=language
        )
        if source_root is None:
            return fallback

        root = Path(source_root).resolve()
        file_path = (root / finding.location.file_path).resolve()
        # 경로 봉쇄 (M-2): 엔진이 절대 경로나 `../` 를 보고하면 루트 밖 파일이
        # LLM 프롬프트에 실려 외부로 나갈 수 있다.
        try:
            contained = file_path == root or file_path.is_relative_to(root)
        except (ValueError, OSError):
            contained = False
        if not contained:
            log.warning(
                "triage 컨텍스트 수집 거부 — 소스 루트를 벗어난 경로: %s",
                finding.location.file_path,
            )
            return fallback

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
            return fallback
        lines = text.splitlines()
        start = max(finding.location.start_line - window - 1, 0)
        end = min(finding.location.start_line + window, len(lines))
        snippet = "\n".join(
            f"{i + 1:>5}: {line}" for i, line in enumerate(lines[start:end], start=start)
        )
        return TriageContext(code_context=snippet, language=language)

    # ---- 응답 파싱 -------------------------------------------------------
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

    import opensast.llm  # noqa: F401 - 내장 프로바이더 등록 보장
    from opensast.plugins.registry import PluginError, llm_registry

    settings = settings or get_settings()
    provider = settings.llm_provider.lower()
    try:
        plugin = llm_registry.get(provider)
    except PluginError as exc:
        log.warning(
            "LLM provider %r 를 레지스트리에서 찾을 수 없어 noop 으로 폴백: %s",
            provider,
            exc,
        )
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
