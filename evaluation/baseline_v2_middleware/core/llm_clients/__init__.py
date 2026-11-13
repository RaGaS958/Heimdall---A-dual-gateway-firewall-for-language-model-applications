"""GUARDIAN v2 — LLM Client Pool. Manages Gemini/Groq/Mistral with fallback chain."""
from __future__ import annotations
from .base import LLMResponse
from .gemini import GeminiClient
from .groq_client import GroqClient
from .mistral import MistralClient
from loguru import logger
from core.circuit_breaker import CircuitBreaker

class LLMClientPool:
    def __init__(self, settings=None):
        if settings is None:
            from config.settings import get_settings
            settings = get_settings()
        self._groq    = GroqClient(settings.groq_api_key)
        self._gemini  = GeminiClient(settings.gemini_api_key)
        self._mistral = MistralClient(settings.mistral_api_key)
        self.primary  = self._groq
        
        self.breakers = {
            "groq": CircuitBreaker("groq"),
            "gemini": CircuitBreaker("gemini"),
            "mistral": CircuitBreaker("mistral")
        }

    async def complete_primary(self, prompt: str, system: str = "", max_tokens: int = 1000) -> LLMResponse:
        """Fallback chain: Groq → Gemini → Mistral."""
        for name, client in [("groq", self._groq), ("gemini", self._gemini), ("mistral", self._mistral)]:
            breaker = self.breakers[name]
            if not breaker.allow_request():
                logger.warning(f"Agentic breaker OPEN for {name} - skipping")
                continue
                
            resp = await client.complete(prompt, system, max_tokens)
            breaker.record_result(resp.ok, 0)
            if resp.ok:
                return resp
                
        return LLMResponse(ok=False, text="", error="All LLM providers failed or breakers open",
                           tokens_input=0, tokens_output=0)

    async def complete_agentic(self, prompt: str, system: str = "", max_tokens: int = 120) -> LLMResponse:
        """Agentic calls: Groq first (fastest), then Gemini."""
        for name, client in [("groq", self._groq), ("gemini", self._gemini)]:
            breaker = self.breakers[name]
            if not breaker.allow_request():
                logger.warning(f"Agentic breaker OPEN for {name} - skipping")
                continue
                
            resp = await client.complete(prompt, system, max_tokens)
            breaker.record_result(resp.ok, 0)
            if resp.ok:
                return resp
                
        # Critical security requirement: if all agentic providers fail (including due to open breaker),
        # return a distinct error that decision_layer will interpret as BLOCK.
        # Returning agentic_breaker_open explicitly triggers fail-closed behavior.
        return LLMResponse(ok=False, text="", error="agentic_breaker_open", tokens_input=0, tokens_output=0)

