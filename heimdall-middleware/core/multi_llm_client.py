"""
HEIMDALL — Multi-LLM Backend Client
Calls the separate multi-llm-backend service (POST /query).
Returns all 3 provider responses + pushes live SSE events per result.

Architecture:
  Heimdall                  multi-llm-backend
  ─────────────────────     ──────────────────
  POST /query     ───────►  asyncio.gather(Gemini, Groq, Mistral)
  wait for all 3  ◄───────  {gemini:{...}, groq:{...}, mistral:{...}}
  push SSE events

Note: we get all 3 back in one HTTP call (the backend does the parallelism).
SSE events are pushed as we parse each provider's result.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import httpx
from loguru import logger

from core.stream_manager import stream_manager

# ── Config ────────────────────────────────────────────────────────────────────
BACKEND_URL     = os.getenv("MULTI_LLM_BACKEND_URL", "http://localhost:8001")
BACKEND_TIMEOUT = float(os.getenv("MULTI_LLM_TIMEOUT", "60"))


# ── Response shape ─────────────────────────────────────────────────────────────

@dataclass
class ProviderResult:
    provider:    str
    text:        str
    ok:          bool
    error:       str
    latency_ms:  float
    model:       str
    tokens_used: int


@dataclass
class MultiLLMResult:
    gemini:     ProviderResult
    groq:       ProviderResult
    mistral:    ProviderResult
    latency_ms: float          # wall-clock for all 3 in parallel

    @property
    def best_response(self) -> Optional[str]:
        """
        Return the first successful response in fallback order: Groq → Gemini → Mistral.
        Used by G2 as the single LLM output to inspect.
        """
        for p in [self.groq, self.gemini, self.mistral]:
            if p.ok and p.text.strip():
                return p.text
        return None

    @property
    def any_ok(self) -> bool:
        return any(p.ok for p in [self.gemini, self.groq, self.mistral])

    def to_dict(self, redact: bool = False) -> dict:
        return {
            "gemini":  _provider_dict(self.gemini, redact),
            "groq":    _provider_dict(self.groq, redact),
            "mistral": _provider_dict(self.mistral, redact),
            "latency_ms": self.latency_ms,
        }

def _provider_dict(p: ProviderResult, redact: bool = False) -> dict:
    return {
        "text":        p.text if not redact else "[REDACTED]",
        "ok":          p.ok,
        "error":       p.error,
        "error_code":  classify_error(p.error) if not p.ok else "",
        "latency_ms":  p.latency_ms,
        "model":       p.model,
        "tokens_used": p.tokens_used,
    }

def _parse_provider(data: dict, name: str) -> ProviderResult:
    p = data.get(name, {})
    return ProviderResult(
        provider    = name,
        text        = p.get("text", ""),
        ok          = bool(p.get("ok", False)),
        error       = p.get("error", ""),
        latency_ms  = float(p.get("latency_ms", 0)),
        model       = p.get("model", ""),
        tokens_used = int(p.get("tokens_used", 0)),
    )


# ── Main client call ──────────────────────────────────────────────────────────

async def query_multi_llm(
    prompt:     str,
    session_id: str,
    system:     Optional[str] = None,
    max_tokens: int           = 1000,
) -> MultiLLMResult:
    """
    Call the multi-llm-backend, push SSE events per provider result.
    Never raises — returns MultiLLMResult with ok=False entries on failure.
    """
    # Emit: LLM phase starting
    stream_manager.push(session_id, {
        "event":     "llm_start",
        "providers": ["gemini", "groq", "mistral"],
    })

    try:
        from config.settings import get_settings
        internal_key = get_settings().internal_auth_key
        
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(BACKEND_TIMEOUT)
        ) as client:
            r = await client.post(
                f"{BACKEND_URL}/query",
                json={
                    "prompt":     prompt,
                    "session_id": session_id,
                    "system":     system,
                    "max_tokens": max_tokens,
                },
                headers={"X-Heimdall-Internal-Key": internal_key}
            )
            r.raise_for_status()
            data = r.json()

    except httpx.TimeoutException:
        err = "multi-llm-backend timeout"
        logger.error(f"[{session_id[:8]}] {err}")
        _push_all_failed(session_id, err)
        return _all_failed(err)

    except httpx.HTTPStatusError as e:
        err = f"multi-llm-backend HTTP {e.response.status_code}"
        logger.error(f"[{session_id[:8]}] {err}")
        _push_all_failed(session_id, err)
        return _all_failed(err)

    except Exception as e:
        err = f"multi-llm-backend error: {str(e)[:100]}"
        logger.error(f"[{session_id[:8]}] {err}")
        _push_all_failed(session_id, err)
        return _all_failed(err)

    # Parse results
    gemini  = _parse_provider(data, "gemini")
    groq    = _parse_provider(data, "groq")
    mistral = _parse_provider(data, "mistral")
    wall_ms = float(data.get("latency_ms", 0))

    # Emit one SSE event per provider (sorted fastest first for visual impact)
    for p in sorted([gemini, groq, mistral], key=lambda x: x.latency_ms):
        stream_manager.push(session_id, {
            "event":        "llm_result",
            "provider":     p.provider,
            "ok":           p.ok,
            "latency_ms":   round(p.latency_ms, 1),
            "tokens_used":  p.tokens_used,
            "model":        p.model,
            "error":        p.error,
            "error_code":   classify_error(p.error) if not p.ok else "",
            # Status only. Text is released in the "complete" event after Gateway 2;
            # a preview here would hand unscreened model output to the browser.
        })

    result = MultiLLMResult(
        gemini=gemini, groq=groq, mistral=mistral, latency_ms=wall_ms
    )
    logger.info(
        f"[{session_id[:8]}] MultiLLM: "
        f"gemini={'OK' if gemini.ok else 'FAIL'} "
        f"groq={'OK' if groq.ok else 'FAIL'} "
        f"mistral={'OK' if mistral.ok else 'FAIL'} "
        f"wall={wall_ms:.0f}ms"
    )
    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def classify_error(error: str) -> str:
    """Stable, secret-free failure code for the UI."""
    low = (error or "").lower()
    if "api key not set" in low or "not set" in low:
        return "no_api_key"
    if "timeout" in low:
        return "timeout"
    if "429" in low or "rate" in low or "quota" in low:
        return "rate_limited"
    if "401" in low or "403" in low:
        return "auth_failed"
    if "404" in low or "model" in low or "decommission" in low:
        return "model_unavailable"
    if "breaker" in low or "circuit" in low:
        return "circuit_open"
    if "backend" in low or "connect" in low:
        return "backend_unreachable"
    return "upstream_error" if low else ""


def _push_all_failed(session_id: str, error: str) -> None:
    for p in ["gemini", "groq", "mistral"]:
        stream_manager.push(session_id, {
            "event":    "llm_result",
            "provider": p,
            "ok":       False,
            "error":    error,
            "error_code": classify_error(error),
            "latency_ms": 0,
        })


def _all_failed(error: str) -> MultiLLMResult:
    fail = lambda p: ProviderResult(
        provider=p, text="", ok=False, error=error,
        latency_ms=0, model="", tokens_used=0
    )
    return MultiLLMResult(
        gemini=fail("gemini"), groq=fail("groq"), mistral=fail("mistral"),
        latency_ms=0
    )
