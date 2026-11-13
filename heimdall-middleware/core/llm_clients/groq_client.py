from __future__ import annotations
import httpx

from config.settings import get_settings
from .base import LLMResponse

GROQ_MODEL = get_settings().groq_model
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"

def _payload(messages, max_tokens, temperature):
    body = {"model": GROQ_MODEL, "messages": messages, "max_completion_tokens": max_tokens, "temperature": temperature}
    effort = get_settings().agentic_reasoning_effort
    if effort and GROQ_MODEL.startswith("openai/gpt-oss"):
        body["reasoning_effort"] = effort  # only gpt-oss accepts it; other models would reject the field
    return body


class GroqClient:
    name = "groq"
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def complete(self, prompt: str, system: str = "", max_tokens: int = 1000, temperature: float = 0.0) -> LLMResponse:
        if not self.api_key or "your_" in self.api_key:
            return LLMResponse(ok=False, text="", error="Groq API key not set", name="groq")
        messages = []
        if system:
            messages.append({"role":"system","content":system})
        messages.append({"role":"user","content":prompt})
        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                r = await c.post(GROQ_URL, headers={"Authorization":f"Bearer {self.api_key}"},
                                 json=_payload(messages, max_tokens, temperature))
            r.raise_for_status()
            d   = r.json()
            tok = d.get("usage",{})
            choice = d["choices"][0]
            text = (choice["message"].get("content") or "").strip()
            if not text:
                return LLMResponse(ok=False, text="", name="groq",
                                   error=f"empty reply (finish reason: {choice.get('finish_reason', 'unknown')})",
                                   tokens_input=tok.get("prompt_tokens",0), tokens_output=tok.get("completion_tokens",0))
            return LLMResponse(ok=True, text=text,
                               model=GROQ_MODEL, name="groq",
                               tokens_input=tok.get("prompt_tokens",0),
                               tokens_output=tok.get("completion_tokens",0))
        except Exception as e:
            return LLMResponse(ok=False, text="", error=type(e).__name__ if not isinstance(e, httpx.HTTPStatusError) else f"HTTP {e.response.status_code}", name="groq")
