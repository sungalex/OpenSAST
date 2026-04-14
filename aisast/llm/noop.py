"""LLM 비활성 환경용 더미 클라이언트."""

from __future__ import annotations

import json

from aisast.llm.base import LLMClient, LLMResponse


class NoopLLMClient(LLMClient):
    name = "noop"

    def complete(self, system: str, user: str) -> LLMResponse:  # noqa: ARG002
        payload = {
            "verdict": "needs_review",
            "fp_probability": 50,
            "rationale": "LLM 비활성 모드로 진단원 수동 확인 필요",
            "recommended_fix": None,
            "patched_code": None,
        }
        return LLMResponse(text=json.dumps(payload, ensure_ascii=False), model="noop")
