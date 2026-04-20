"""LLM 클라이언트 공통 인터페이스."""

from __future__ import annotations

import abc
from dataclasses import dataclass


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


class LLMClient(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def complete(self, system: str, user: str) -> LLMResponse:
        """system + user 프롬프트로 LLM 응답을 생성."""
