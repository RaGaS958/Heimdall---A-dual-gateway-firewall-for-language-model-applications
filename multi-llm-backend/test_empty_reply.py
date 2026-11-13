"""A 200 response with no text is a failure, not a success with an empty answer."""
import asyncio

import httpx

import clients


def _serve(monkeypatch, payload):
    class Fake:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return httpx.Response(200, json=payload, request=httpx.Request("POST", "https://example.test"))
    monkeypatch.setattr(clients.httpx, "AsyncClient", Fake)


def test_openai_style_empty_content_is_not_ok(monkeypatch):
    _serve(monkeypatch, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {"total_tokens": 20}})
    for call in (clients.call_groq, clients.call_mistral):
        result = asyncio.run(call("hi", None, "k", 20))
        assert not result.ok and "empty reply" in result.error and "length" in result.error


def test_gemini_empty_parts_is_not_ok(monkeypatch):
    _serve(monkeypatch, {"candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}], "usageMetadata": {"totalTokenCount": 20}})
    result = asyncio.run(clients.call_gemini("hi", None, "k", 20))
    assert not result.ok and "MAX_TOKENS" in result.error


def test_a_real_answer_is_still_ok(monkeypatch):
    _serve(monkeypatch, {"choices": [{"message": {"content": "ready"}, "finish_reason": "stop"}], "usage": {"total_tokens": 9}})
    assert asyncio.run(clients.call_groq("hi", None, "k", 20)).text == "ready"
