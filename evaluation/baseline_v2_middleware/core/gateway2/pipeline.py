"""
HEIMDALL — Gateway 2: Output Sentinel Pipeline  [PATCHED]
Identical to Guardian v2 gateway2/pipeline.py with one addition:
  - Optional `session_id` parameter on process()
  - Emits SSE layer events via stream_manager after each output check

All existing logic, verdicts, and cache behaviour are unchanged.
"""
from __future__ import annotations
import asyncio
import hashlib
import time
from typing import Optional
from loguru import logger

from core.models import RequestContext, Verdict, Flag, FlagSource, AttackFamily
from core.cache.manager import CacheManager
from core.agentic.decision_layer import AgenticDecisionLayer
from core.stream_manager import stream_manager
from .o2_leakage import LeakageDetector
from .o3_behavior import BehavioralChecker
from .o4_tool_validator import ToolValidator


class OutputSentinel:

    def __init__(self,
                 cache:    CacheManager,
                 agentic:  AgenticDecisionLayer,
                 leakage:  LeakageDetector,
                 behavior: BehavioralChecker,
                 tools:    ToolValidator):
        self.cache    = cache
        self.agentic  = agentic
        self.leakage  = leakage
        self.behavior = behavior
        self.tools    = tools
        self._stats   = {"total": 0, "blocked": 0, "sanitized": 0, "passed": 0}

    # ── SSE emit helper ───────────────────────────────────────────────────────

    def _emit(self, session_id: Optional[str], event: dict) -> None:
        if session_id:
            stream_manager.push(session_id, event)

    # ── Main pipeline ─────────────────────────────────────────────────────────

    async def process(
        self,
        ctx: RequestContext,
        session_id: Optional[str] = None,   # ← enables SSE streaming
        skip_layers: Optional[frozenset] = None,  # ← Phase 3: ablation research only
    ) -> RequestContext:
        """
        Process a response through the G2 output security pipeline.

        Args:
            ctx:         The request context containing the LLM response.
            session_id:  SSE session ID for streaming events (optional).
            skip_layers: [RESEARCH ONLY] Set of layer names to bypass for
                         ablation studies. NOT available on production /chat endpoint.
                         Example: frozenset({"O2_LEAKAGE", "O3_BEHAVIOR"})
        """
        skip_layers = skip_layers or frozenset()
        t_start = time.perf_counter()
        self._stats["total"] += 1
        output = ctx.llm_raw_output
        output_flags: list[Flag] = []

        # ── O1: Output cache check ────────────────────────────────────────────
        t_o1 = time.perf_counter()
        hot_hit = self.cache.hot.check(output)
        o1_ms   = (time.perf_counter() - t_o1) * 1000

        ctx.trace_data["output_stage"].append({
            "layer": "O1",
            "name": "Output Cache",
            "hit": bool(hot_hit),
            "duration_ms": o1_ms
        })

        if hot_hit and hot_hit.get("family") == "BAD_OUTPUT":
            ctx.g2_verdict    = Verdict.BLOCK
            ctx.g2_confidence = 1.0
            ctx.g2_reasoning  = "Output matched known-bad cache entry"
            ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
            ctx.final_output  = "I'm unable to return that response."
            self._stats["blocked"] += 1

            self._emit(session_id, {
                "event": "layer", "gateway": "G2", "layer": "O1",
                "name": "Output Cache", "status": "BLOCK",
                "latency_ms": round(o1_ms, 2),
            })
            self._emit(session_id, {
                "event": "verdict", "gateway": "G2",
                "verdict": "BLOCK", "confidence": 1.0,
                "latency_ms": round(ctx.g2_latency_ms, 1),
            })
            logger.warning(f"G2 [{ctx.request_id[:8]}]: BLOCK (output cache hit)")
            return ctx

        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O1",
            "name": "Output Cache", "status": "MISS",
            "latency_ms": round(o1_ms, 2),
        })

        # ── O2 ∥ O3 ∥ O4: Output checks in parallel ───────────────────────────
        t_o234 = time.perf_counter()
        loop    = asyncio.get_event_loop()

        # Dummy returns if skipped
        async def skip_leakage(): return (0.0, False, [])
        async def skip_behavior(): return (0.0, [])
        async def skip_tool(): return []

        (leakage_score, pii_detected, leak_flags), (drift_score, behav_flags), tool_flags = await asyncio.gather(
            loop.run_in_executor(None, self.leakage.check, ctx) if "O2_LEAKAGE" not in skip_layers else skip_leakage(),
            loop.run_in_executor(None, self.behavior.check, ctx) if "O3_BEHAVIOR" not in skip_layers else skip_behavior(),
            loop.run_in_executor(None, self.tools.validate, ctx) if "O4_TOOL" not in skip_layers else skip_tool()
        )

        o234_ms      = (time.perf_counter() - t_o234) * 1000
        output_flags = leak_flags + behav_flags + tool_flags
        for f in output_flags:
            ctx.add_flag(f)
            
        ctx.trace_data["output_stage"].extend([
            {
                "layer": "O2",
                "name": "Leakage Detector",
                "leakage_score": leakage_score,
                "pii_detected": pii_detected,
                "flags": [f.to_compressed_dict() for f in leak_flags],
                "duration_ms": o234_ms
            },
            {
                "layer": "O3",
                "name": "Behavior Checker",
                "drift_score": drift_score,
                "flags": [f.to_compressed_dict() for f in behav_flags],
                "duration_ms": o234_ms
            },
            {
                "layer": "O4",
                "name": "Tool Validator",
                "flags": [f.to_compressed_dict() for f in tool_flags],
                "duration_ms": o234_ms
            }
        ])

        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O2",
            "name": "Leakage Detector",
            "status": "DISABLED" if "O2_LEAKAGE" in skip_layers else ("FLAG" if leak_flags else "PASS"),
            "latency_ms": round(o234_ms, 2),
            "leakage_score": round(leakage_score, 3),
            "pii_detected": pii_detected,
            "flags": len(leak_flags),
        })
        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O3",
            "name": "Behavior Checker",
            "status": "DISABLED" if "O3_BEHAVIOR" in skip_layers else ("FLAG" if behav_flags else "PASS"),
            "latency_ms": round(o234_ms, 2),
            "drift_score": round(drift_score, 3),
            "flags": len(behav_flags),
        })
        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O4",
            "name": "Tool Validator",
            "status": "DISABLED" if "O4_TOOL" in skip_layers else ("FLAG" if tool_flags else "PASS"),
            "latency_ms": round(o234_ms, 2),
            "flags": len(tool_flags),
        })

        baseline_turns = ctx.session.turn_count if ctx.session else 0

        # ── Decide: escalate to agentic? ──────────────────────────────────────
        if not output_flags:
            ctx.g2_verdict    = Verdict.PASS
            ctx.g2_confidence = 0.95
            ctx.g2_reasoning  = "No output violations detected"
            ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
            ctx.final_output  = output
            self._stats["passed"] += 1
            if ctx.session:
                ctx.session.turn_count += 1
            self._emit(session_id, {
                "event": "verdict", "gateway": "G2",
                "verdict": "PASS", "confidence": 0.95,
                "latency_ms": round(ctx.g2_latency_ms, 1),
            })
            logger.debug(f"G2 [{ctx.request_id[:8]}]: PASS (clean output) {ctx.g2_latency_ms:.1f}ms")
            return ctx

        # ── Fast path: Auto-block on critical output flags ────────────────────
        if ctx.has_critical_flag:
            ctx.g2_verdict    = Verdict.BLOCK
            ctx.g2_confidence = 0.99
            ctx.g2_reasoning  = "Critical leakage or violation detected"
            ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
            ctx.final_output  = "[REDACTED BY HEIMDALL OUTPUT SENTINEL]"
            self._stats["blocked"] += 1
            self._emit(session_id, {
                "event": "verdict", "gateway": "G2",
                "verdict": "BLOCK", "confidence": 0.99,
                "latency_ms": round(ctx.g2_latency_ms, 1),
                "attack_type": "LEAKAGE",
            })
            logger.warning(f"G2 [{ctx.request_id[:8]}]: AUTO-BLOCK (critical flag)")
            return ctx

        # ── O5: Output Agentic Decision ────────────────────────────────────────
        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O5",
            "name": "Agentic Decision", "status": "RUNNING" if "AGENTIC" not in skip_layers else "DISABLED", "latency_ms": 0.0,
            "flags": len(output_flags),
        })
        t_o5 = time.perf_counter()
        
        if "AGENTIC" not in skip_layers:
            decision = await self.agentic.decide_output(
                ctx,
                leakage_score  = leakage_score,
                pii_detected   = pii_detected,
                drift_score    = drift_score,
                baseline_turns = baseline_turns,
            )
        else:
            from core.models import AgenticDecision
            decision = AgenticDecision(
                verdict=Verdict.PASS,
                confidence=0.5,
                reason="Agentic layer bypassed (ablation)",
                attack_type=AttackFamily.UNKNOWN,
            )
            
        o5_ms = (time.perf_counter() - t_o5) * 1000

        ctx.g2_verdict    = decision.verdict
        ctx.g2_confidence = decision.confidence
        ctx.g2_reasoning  = decision.reason
        ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000

        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O5",
            "name": "Agentic Decision",
            "status": "DISABLED" if "AGENTIC" in skip_layers else decision.verdict.value,
            "latency_ms": round(o5_ms, 2),
            "confidence": round(decision.confidence, 3),
            "reason": decision.reason[:80],
        })

        if decision.verdict == Verdict.BLOCK:
            ctx.final_output = (getattr(decision, "user_response", None)
                                or "I'm unable to return that response.")
            self._stats["blocked"] += 1
            self.cache.hot.store(output, {
                "family": "BAD_OUTPUT", "severity": 9, "source": "g2_block"
            })
        elif decision.verdict == Verdict.SANITIZE:
            # sanitized_output was added to AgenticDecision in models.py fix.
            # getattr fallback prevents AttributeError if running an older models.py.
            sanitized = (getattr(decision, "sanitized_output", None)
                         or getattr(decision, "sanitized_input", None))
            ctx.g2_sanitized_output = sanitized
            ctx.final_output = sanitized or self._basic_sanitize(output)
            self._stats["sanitized"] += 1
        else:
            ctx.final_output = output
            self._stats["passed"] += 1

        if ctx.session:
            ctx.session.turn_count += 1

        self._emit(session_id, {
            "event": "verdict", "gateway": "G2",
            "verdict": decision.verdict.value,
            "confidence": round(decision.confidence, 3),
            "latency_ms": round(ctx.g2_latency_ms, 1),
        })
        logger.info(
            f"G2 [{ctx.request_id[:8]}]: {decision.verdict.value} "
            f"conf={decision.confidence:.2f} output_flags={len(output_flags)} "
            f"latency={ctx.g2_latency_ms:.0f}ms"
        )
        return ctx

    def _basic_sanitize(self, output: str) -> str:
        import re
        for pattern in [
            r"(?i)(my system prompt|initial instructions?|I was instructed to)[^.]*\.",
            r"(?i)(I have been|I am) (configured|programmed|told)[^.]*\.",
        ]:
            output = re.sub(pattern, "[redacted]", output)
        output = re.sub(r"sk-[A-Za-z0-9]{32,}", "[REDACTED_KEY]", output)
        output = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "[REDACTED_TOKEN]", output)
        return output.strip()

    @property
    def stats(self) -> dict:
        t = self._stats["total"]
        return {
            **self._stats,
            "block_rate":    round(self._stats["blocked"]   / t, 3) if t else 0,
            "sanitize_rate": round(self._stats["sanitized"] / t, 3) if t else 0,
        }