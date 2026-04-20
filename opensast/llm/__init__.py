"""LLM 기반 지능형 후처리 모듈.

내장 LLM 프로바이더는 import 시점에 플러그인 레지스트리에 등록된다.
"""

from opensast.llm.anthropic import AnthropicClient
from opensast.llm.base import LLMClient, LLMError, LLMResponse
from opensast.llm.noop import NoopLLMClient
from opensast.llm.ollama import OllamaClient
from opensast.llm.triage import Triager, TriageContext
from opensast.plugins.registry import llm_registry

# 내장 프로바이더 등록 (priority=50 = 내장 기본값)
llm_registry.register("ollama", OllamaClient, source="builtin", priority=50)
llm_registry.register("anthropic", AnthropicClient, source="builtin", priority=50)
llm_registry.register("noop", NoopLLMClient, source="builtin", priority=50)

__all__ = [
    "LLMClient",
    "LLMError",
    "LLMResponse",
    "Triager",
    "TriageContext",
    "AnthropicClient",
    "NoopLLMClient",
    "OllamaClient",
]
