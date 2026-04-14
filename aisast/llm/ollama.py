"""Ollama/Gemma 로컬 LLM 클라이언트."""

from __future__ import annotations

import httpx

from aisast.config import Settings, get_settings
from aisast.llm.base import LLMClient, LLMError, LLMResponse


class OllamaClient(LLMClient):
    name = "ollama"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def complete(self, system: str, user: str) -> LLMResponse:
        url = f"{self.settings.ollama_host.rstrip('/')}/api/chat"
        payload = {
            "model": self.settings.ollama_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }
        try:
            resp = httpx.post(
                url,
                json=payload,
                timeout=self.settings.llm_timeout_seconds,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMError(f"ollama request failed: {exc}") from exc
        data = resp.json()
        content = (
            data.get("message", {}).get("content")
            or data.get("response")
            or ""
        )
        if not content:
            raise LLMError("ollama returned empty response")
        return LLMResponse(text=content, model=self.settings.ollama_model)
