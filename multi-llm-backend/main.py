"""
Multi-LLM Backend — FastAPI Application
Sits BEHIND Heimdall. Receives clean prompts, fires all 3 LLMs in parallel.

Endpoints:
  POST /query       — parallel LLM call (main endpoint)
  GET  /health      — provider status + API key check
  GET  /            — root (HuggingFace Space landing)
"""
from __future__ import annotations

import hmac
import os
import time
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from clients import call_all_parallel, LLMResponse
from pydantic import BaseModel, Field

load_dotenv()

# ── Config from env ───────────────────────────────────────────────────────────
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")
DEFAULT_SYSTEM  = os.getenv(
    "DEFAULT_SYSTEM",
    "You are a helpful, concise assistant. Answer clearly and briefly.",
)
HEIMDALL_ENV = os.getenv("HEIMDALL_ENV", "development").lower()
INTERNAL_AUTH_KEY = os.getenv("INTERNAL_AUTH_KEY", "")
if not INTERNAL_AUTH_KEY or INTERNAL_AUTH_KEY == "heimdall-internal-dev-key":
    if HEIMDALL_ENV == "production":
        raise RuntimeError("INTERNAL_AUTH_KEY must be set in production")
    # Fail closed: with no shared secret configured, /query rejects every caller.
    INTERNAL_AUTH_KEY = ""

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    docs_url=None if HEIMDALL_ENV == "production" else "/docs",
    redoc_url=None,
    openapi_url=None if HEIMDALL_ENV == "production" else "/openapi.json",
    title="Heimdall — Multi-LLM Backend",
    description="Fires Gemini, Groq, and Mistral in parallel. Sits behind Heimdall firewall.",
    version="1.0.0",
)

middleware_url = os.getenv("MIDDLEWARE_URL", "http://localhost:8000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in middleware_url.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["content-type", "x-heimdall-internal-key"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    prompt:     str           = Field(..., min_length=1, max_length=70000,
                                      description="Sanitised input from Heimdall G1")
    session_id: Optional[str] = Field(None, description="Passed through for logging")
    system:     Optional[str] = Field(None, max_length=20000, description="Override system prompt")
    max_tokens: int           = Field(1000, ge=50, le=4000)


class ProviderResult(BaseModel):
    text:        str
    ok:          bool
    error:       str
    latency_ms:  float
    model:       str
    tokens_used: int


class QueryResponse(BaseModel):
    gemini:      ProviderResult
    groq:        ProviderResult
    mistral:     ProviderResult
    session_id:  Optional[str]
    latency_ms:  float          # wall-clock time for all 3 in parallel


class HealthResponse(BaseModel):
    status:     str
    providers:  dict[str, dict]


# ── Helper ────────────────────────────────────────────────────────────────────

def _llm_resp_to_schema(r: LLMResponse) -> ProviderResult:
    return ProviderResult(
        text=r.text,
        ok=r.ok,
        error=r.error,
        latency_ms=round(r.latency_ms, 1),
        model=r.model,
        tokens_used=r.tokens_used,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "Heimdall Multi-LLM Backend",
        "status":  "running",
        "docs":    "/docs",
    }


@app.post("/query", response_model=QueryResponse)
async def query(req: QueryRequest, request: Request):
    """
    Fire Gemini + Groq + Mistral in parallel via asyncio.gather.
    Returns all 3 responses. Individual provider failures return ok=False
    but never cause a 500 — the demo must never crash.
    """
    auth_header = request.headers.get("x-heimdall-internal-key", "")
    if not INTERNAL_AUTH_KEY or not hmac.compare_digest(auth_header.encode(), INTERNAL_AUTH_KEY.encode()):
        raise HTTPException(status_code=403, detail="Invalid internal auth key")
    t0     = time.perf_counter()
    system = req.system or DEFAULT_SYSTEM

    results = await call_all_parallel(
        prompt      = req.prompt,
        system      = system,
        gemini_key  = GEMINI_API_KEY,
        groq_key    = GROQ_API_KEY,
        mistral_key = MISTRAL_API_KEY,
        max_tokens  = req.max_tokens,
    )

    wall_ms = (time.perf_counter() - t0) * 1000

    return QueryResponse(
        gemini     = _llm_resp_to_schema(results["gemini"]),
        groq       = _llm_resp_to_schema(results["groq"]),
        mistral    = _llm_resp_to_schema(results["mistral"]),
        session_id = req.session_id,
        latency_ms = round(wall_ms, 1),
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Check which providers have API keys configured.
    Does NOT make live calls — just key presence check.
    """
    def _key_status(key: str, label: str) -> dict:
        has_key = bool(key and not key.startswith("your_"))
        return {
            "configured": has_key,
            "hint": f"Set {label} in .env" if not has_key else "ready",
        }

    all_configured = all([
        bool(GEMINI_API_KEY),
        bool(GROQ_API_KEY),
        bool(MISTRAL_API_KEY),
    ])

    from clients import breakers
    
    return HealthResponse(
        status="ok" if all_configured else "degraded",
        providers={
            "gemini":  {**_key_status(GEMINI_API_KEY,  "GEMINI_API_KEY"), "breaker": breakers["gemini"].get_state_dict()},
            "groq":    {**_key_status(GROQ_API_KEY,    "GROQ_API_KEY"), "breaker": breakers["groq"].get_state_dict()},
            "mistral": {**_key_status(MISTRAL_API_KEY, "MISTRAL_API_KEY"), "breaker": breakers["mistral"].get_state_dict()},
        },
    )


# ── Dev runner ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=HEIMDALL_ENV != "production")
