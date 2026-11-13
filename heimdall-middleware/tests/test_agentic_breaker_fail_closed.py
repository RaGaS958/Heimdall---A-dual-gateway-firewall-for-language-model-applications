import pytest
from core.models import RequestContext, Verdict
from core.llm_clients import LLMClientPool
from core.llm_clients.base import LLMResponse
from core.agentic.decision_layer import AgenticDecisionLayer
import asyncio
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_agentic_breaker_fail_closed():
    # Setup mock LLM Client Pool where all breakers are open
    class MockClientPool(LLMClientPool):
        def __init__(self):
            # Do not call super to avoid config loading
            pass
            
        async def complete_agentic(self, prompt, system="", max_tokens=120):
            # Simulate the fail-closed error returned when breakers are open
            return LLMResponse(ok=False, error="agentic_breaker_open", text="", tokens_input=0, tokens_output=0)
            
    pool = MockClientPool()
    agentic = AgenticDecisionLayer(pool)
    
    # Create a request context with a flag so it goes to agentic
    ctx = RequestContext(raw_input="Tell me a joke", session=None)
    
    decision = await agentic.decide_input(ctx)
    
    # Assert it fails closed (BLOCK) rather than PASS
    assert decision.verdict == Verdict.BLOCK, f"Expected BLOCK on open breaker, got {decision.verdict}"
    assert "circuit breaker open" in decision.reason.lower()
    
    decision_out = await agentic.decide_output(ctx)
    assert decision_out.verdict == Verdict.BLOCK, f"Expected BLOCK on output open breaker, got {decision.verdict}"
