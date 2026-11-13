"""
Heimdall audit — dynamic harness, part 2: agentic fail-open, SSE session
isolation, warm-cache mock-encoder quality. All network calls to
Gemini/Groq/Mistral are mocked -- this sandbox has no egress to those
providers, so this tests the MIDDLEWARE's own failure-handling logic
deterministically rather than depending on live provider behavior.
"""
import sys, asyncio, json
sys.path.insert(0, ".")

from core.models import RequestContext, Flag, FlagSource, AttackFamily, SessionState
from core.agentic.decision_layer import AgenticDecisionLayer
from core.llm_clients import LLMResponse

print("=" * 70)
print("TEST 5 — Agentic layer fail-open behavior under provider failure")
print("=" * 70)

def make_ctx(num_flags=1, severity=6, confidence=0.6):
    ctx = RequestContext(raw_input="some moderately suspicious but not obviously extreme text")
    ctx.canonical_input = ctx.raw_input
    for i in range(num_flags):
        ctx.flags.append(Flag(
            source=FlagSource.PATTERN,
            attack_families=[AttackFamily.INSTRUCTION_OVERRIDE],
            severity=severity,
            confidence=confidence,
            evidence=f"synthetic evidence {i}",
        ))
    return ctx

class FakePoolAlwaysFails:
    async def complete_agentic(self, *a, **kw):
        # Simulates: provider timeout / network error / 5xx -- ok=False
        return LLMResponse(ok=False, text="", name="mock", error="simulated timeout")

class FakePoolMalformed:
    async def complete_agentic(self, *a, **kw):
        # Simulates: provider responds but with non-JSON / garbled text
        return LLMResponse(ok=True, text="I'm not sure how to format this as JSON, sorry!", name="mock")

class FakePoolValidBlock:
    async def complete_agentic(self, *a, **kw):
        payload = {"verdict":"BLOCK","confidence":0.95,"attack_confirmed":True,
                   "attack_type":"INSTRUCTION_OVERRIDE","reason":"clear override attempt",
                   "cache_action":"STORE_BAD","sanitized_input":None,"user_response":None}
        return LLMResponse(ok=True, text=json.dumps(payload), name="mock")

async def run_case(label, pool, ctx):
    layer = AgenticDecisionLayer(pool)
    decision = await layer.decide_input(ctx)
    print(f"\n[{label}]")
    print(f"  ctx: flag_count={ctx.flag_count} max_severity={ctx.max_severity} has_critical={ctx.has_critical_flag}")
    print(f"  -> AgenticDecision.verdict = {decision.verdict.value}  (confidence={decision.confidence})")
    print(f"     reason: {decision.reason}")
    return decision.verdict.value

async def main():
    # Case A: moderately flagged (escalation-eligible, NOT critical fast-path) + provider fully down
    ctx_a = make_ctx(num_flags=2, severity=6)
    v_a = await run_case("Moderate flags (2x sev=6, non-critical) + provider DOWN (ok=False)", FakePoolAlwaysFails(), ctx_a)

    # Case B: same moderate flags, but provider returns malformed (non-JSON) text
    ctx_b = make_ctx(num_flags=2, severity=6)
    v_b = await run_case("Moderate flags (2x sev=6, non-critical) + provider returns MALFORMED text", FakePoolMalformed(), ctx_b)

    # Case C: same moderate flags, provider healthy and correctly says BLOCK (control/sanity case)
    ctx_c = make_ctx(num_flags=2, severity=6)
    v_c = await run_case("Moderate flags (2x sev=6, non-critical) + provider HEALTHY, says BLOCK", FakePoolValidBlock(), ctx_c)

    # Case D: critical flag + very high severity -> should hit the fast-path auto-block
    # BEFORE ever calling the (down) provider
    ctx_d = make_ctx(num_flags=3, severity=10, confidence=0.9)  # has_critical (sev>=9) AND combined_severity(=27) > 25
    v_d = await run_case("CRITICAL: 3x severity=10 flags, combined=27>25 (fast-path range) + provider DOWN", FakePoolAlwaysFails(), ctx_d)

    print("\n>>> CONCLUSION T5:")
    print(f"    Provider fully down on a MODERATE (non-critical) escalation  -> verdict = {v_a}")
    print(f"    Provider returns garbage/non-JSON on the SAME moderate case -> verdict = {v_b}")
    print(f"    Provider healthy, correctly identifies the attack           -> verdict = {v_c}")
    print(f"    CRITICAL/high-severity flag, provider ALSO down             -> verdict = {v_d}")
    if v_a == "PASS" and v_b == "PASS" and v_c == "BLOCK":
        print("    CONFIRMED: any agentic-provider failure (timeout, network error, OR a")
        print("    malformed/non-JSON response) on a moderately-flagged, non-critical input")
        print("    fails OPEN (PASS) -- identical to a provider that is healthy but simply")
        print("    disagrees. The system cannot distinguish 'the judge is unavailable' from")
        print("    'the judge looked and found nothing', for anything below the severity>25")
        print("    +critical fast-path.")
    if v_d == "BLOCK":
        print("    The severity>25+critical fast-path DOES correctly fail closed without")
        print("    depending on the (down) provider at all -- this is the one safety net.")

asyncio.run(main())

print()
print("=" * 70)
print("TEST 6 — SSE session isolation: can a second listener on the same")
print("session_id receive another 'user' conversation's events?")
print("=" * 70)

from core.stream_manager import StreamManager

async def sse_test():
    sm = StreamManager()
    SHARED_SID = "alice"   # attacker guesses/reuses this session_id string

    received_by_attacker = []

    async def attacker_listener():
        async for raw in sm.listen(SHARED_SID, timeout=3):
            evt = json.loads(raw)
            received_by_attacker.append(evt)
            if evt.get("event") == "complete":
                break

    listener_task = asyncio.create_task(attacker_listener())
    await asyncio.sleep(0.1)  # let the listener attach first

    # "Victim" makes a chat request using the SAME session_id (e.g. attacker
    # simply always opens /stream/alice and separately gets a real user, or
    # some other part of the app, to use session_id=alice)
    sm.push(SHARED_SID, {"event": "layer", "layer": "L1", "verdict": "PASS"})
    sm.push(SHARED_SID, {"event": "llm_result", "provider": "gemini",
                          "text_preview": "VICTIM_SECRET_CONTENT_PREVIEW..."})
    sm.push(SHARED_SID, {"event": "complete", "reply": "victim's real reply text",
                          "llm_responses": {"gemini": {"text": "full unfiltered victim answer"}}})

    await listener_task

    print(f"\nEvents an independent listener on session_id={SHARED_SID!r} received "
          f"(without ever sending the request itself):")
    for e in received_by_attacker:
        print(f"   {e}")

    leaked = any("VICTIM_SECRET" in json.dumps(e) or "victim" in json.dumps(e).lower() for e in received_by_attacker)
    print(f"\n>>> CONCLUSION T6: cross-listener leakage via shared/guessed session_id = {leaked}")
    print("    session_id is a bare client-supplied string with no ownership/auth check")
    print("    anywhere in StreamManager or in POST /chat -- isolation depends entirely on")
    print("    session_id being unguessable, which is NOT enforced (client can supply any")
    print("    string in ChatRequest.session_id).")

asyncio.run(sse_test())
