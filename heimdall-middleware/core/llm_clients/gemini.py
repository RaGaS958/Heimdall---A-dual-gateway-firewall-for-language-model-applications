from __future__ import annotations
import httpx

from config.settings import get_settings
from .base import LLMResponse

GEMINI_MODEL = get_settings().gemini_model
GEMINI_URL   = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

class GeminiClient:
    name = "gemini"
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def complete(self, prompt: str, system: str = "", max_tokens: int = 1000, temperature: float = 0.0) -> LLMResponse:
        if not self.api_key or "your_" in self.api_key:
            return LLMResponse(ok=False, text="", error="Gemini API key not set", name="gemini")
        payload = {"contents":[{"role":"user","parts":[{"text":prompt}]}],
                   "generationConfig":{"maxOutputTokens":max_tokens,"temperature":temperature}}
        if system:
            payload["systemInstruction"] = {"parts":[{"text":system}]}
        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                r = await c.post(GEMINI_URL, headers={"x-goog-api-key": self.api_key}, json=payload)
            r.raise_for_status()
            d    = r.json()
            text = " ".join(p.get("text","") for p in d["candidates"][0]["content"]["parts"]).strip()
            tok  = d.get("usageMetadata",{})
            if not text:
                reason = d["candidates"][0].get("finishReason", "unknown")
                return LLMResponse(ok=False, text="", name="gemini", error=f"empty reply (finish reason: {reason})",
                                   tokens_input=tok.get("promptTokenCount",0), tokens_output=tok.get("candidatesTokenCount",0))
            return LLMResponse(ok=True, text=text, model=GEMINI_MODEL, name="gemini",
                               tokens_input=tok.get("promptTokenCount",0),
                               tokens_output=tok.get("candidatesTokenCount",0))
        except Exception as e:
            return LLMResponse(ok=False, text="", error=type(e).__name__ if not isinstance(e, httpx.HTTPStatusError) else f"HTTP {e.response.status_code}", name="gemini")
