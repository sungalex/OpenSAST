"""Anthropic Claude API 기반 LLM 클라이언트."""

from __future__ import annotations

from opensast.config import Settings, get_settings
from opensast.llm.base import LLMClient, LLMError, LLMResponse

try:
    import anthropic  # type: ignore
except ImportError:  # pragma: no cover - optional dependency guard
    anthropic = None


class AnthropicClient(LLMClient):
    name = "anthropic"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        if anthropic is None:
            raise LLMError("anthropic SDK not installed")
        if not self.settings.anthropic_api_key:
            raise LLMError("anthropic_api_key not configured")
        self._client = anthropic.Anthropic(api_key=self.settings.anthropic_api_key)

    def complete(self, system: str, user: str) -> LLMResponse:
        model = self.settings.anthropic_model
        try:
            message = self._client.messages.create(
                model=model,
                max_tokens=2048,
                temperature=0.1,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:  # pragma: no cover - network dependent
            raise LLMError(f"anthropic request failed: {exc}") from exc
        chunks = [c.text for c in message.content if getattr(c, "type", "") == "text"]
        text = "\n".join(chunks).strip()
        if not text:
            raise LLMError("anthropic returned empty response")
        usage = getattr(message, "usage", None)
        return LLMResponse(
            text=text,
            model=model,
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
        )
