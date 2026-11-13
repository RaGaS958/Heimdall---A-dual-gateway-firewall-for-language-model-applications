"""
HEIMDALL Gateway 2: output sentinel.

Decisions use only this response's flags. Earlier builds evaluated the whole request's
flags, so a soft flag from Gateway 1 could turn a harmless answer into an auto-block.
Secrets and personal data are redacted deterministically, and active content is stripped
from every response that is delivered.
"""
from __future__ import annotations
import asyncio
import hashlib
import time
from typing import Optional
from loguru import logger

from core.gateway1.canonicalizer import strip_invisibles
from core.models import RequestContext, Verdict, Flag, FlagSource, AttackFamily
from core.cache.manager import CacheManager
from core.agentic.decision_layer import AgenticDecisionLayer
from core.stream_manager import stream_manager
from .o2_leakage import LeakageDetector, redact
from .o3_behavior import BehavioralChecker
from .o4_tool_validator import ToolValidator, strip_active_content


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
        loop    = asyncio.get_running_loop()

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
        # Output findings are recorded on the request for the trace but must not
        # raise the session's attack score; a model's answer is not a user's act.
        ctx.flags.extend(output_flags)

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

        # ── No findings ───────────────────────────────────────────────────────
        if not output_flags:
            return self._deliver(ctx, session_id, t_start, Verdict.PASS, 0.95, "No output violations detected", output)

        # ── Hard findings block without a model call ──────────────────────────
        if any(f.severity >= 9 for f in output_flags):
            ctx.g2_verdict    = Verdict.BLOCK
            ctx.g2_confidence = 0.99
            ctx.g2_reasoning  = next(f.evidence for f in output_flags if f.severity >= 9)[:200]
            ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
            ctx.final_output  = "[REDACTED BY HEIMDALL OUTPUT SENTINEL]"
            self._stats["blocked"] += 1
            self._emit(session_id, {
                "event": "verdict", "gateway": "G2", "verdict": "BLOCK", "confidence": 0.99,
                "latency_ms": round(ctx.g2_latency_ms, 1), "attack_type": "LEAKAGE",
                "reason": "A critical output rule fired",
            })
            logger.warning(f"G2 [{ctx.request_id[:8]}]: AUTO-BLOCK (critical flag)")
            return ctx

        # ── Low-severity findings are repaired deterministically ──────────────
        if all(f.severity <= 5 for f in output_flags) or (ctx.degraded and all(f.severity < 7 for f in output_flags)):
            return self._deliver(ctx, session_id, t_start, Verdict.SANITIZE, 0.8,
                                 "Personal data or active content removed", self._basic_sanitize(output, ctx))

        # ── O5: arbiter ───────────────────────────────────────────────────────
        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O5",
            "name": "Agentic Decision", "status": "RUNNING" if "AGENTIC" not in skip_layers else "DISABLED",
            "latency_ms": 0.0, "flags": len(output_flags),
        })
        t_o5 = time.perf_counter()

        if "AGENTIC" not in skip_layers:
            decision = await self.agentic.decide_output(
                ctx, leakage_score=leakage_score, pii_detected=pii_detected,
                drift_score=drift_score, baseline_turns=baseline_turns, flags=output_flags,
            )
        else:
            from core.models import AgenticDecision
            decision = AgenticDecision(verdict=Verdict.PASS, confidence=0.5,
                                       reason="Agentic layer bypassed (ablation)", attack_type=AttackFamily.UNKNOWN)
        o5_ms = (time.perf_counter() - t_o5) * 1000

        self._emit(session_id, {
            "event": "layer", "gateway": "G2", "layer": "O5", "name": "Agentic Decision",
            "status": ("DISABLED" if "AGENTIC" in skip_layers
                       else "UNAVAILABLE" if decision.unavailable else decision.verdict.value),
            "latency_ms": round(o5_ms, 2), "confidence": round(decision.confidence, 3),
            "reason": decision.reason[:120],
        })

        if decision.verdict == Verdict.BLOCK:
            ctx.g2_verdict    = Verdict.BLOCK
            ctx.g2_confidence = decision.confidence
            ctx.g2_reasoning  = decision.reason
            ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
            ctx.final_output  = "I'm unable to return that response."
            self._stats["blocked"] += 1
            if not decision.unavailable:
                self.cache.hot.store(output, {"family": "BAD_OUTPUT", "severity": 9, "source": "g2_block"})
            self._emit(session_id, {
                "event": "verdict", "gateway": "G2", "verdict": "BLOCK",
                "confidence": round(decision.confidence, 3), "latency_ms": round(ctx.g2_latency_ms, 1),
                "fail_closed": decision.unavailable,
            })
            return ctx

        if decision.verdict == Verdict.SANITIZE:
            # The arbiter's rewrite is untrusted too, so it gets the same repair pass.
            ctx.g2_sanitized_output = decision.sanitized_output
            return self._deliver(ctx, session_id, t_start, Verdict.SANITIZE, decision.confidence, decision.reason,
                                 self._basic_sanitize(decision.sanitized_output or output, ctx))

        return self._deliver(ctx, session_id, t_start, Verdict.PASS, decision.confidence, decision.reason, output)

    def _deliver(self, ctx, session_id, t_start, verdict, confidence, reason, text) -> RequestContext:
        """Every delivered response is stripped of covert characters and active content."""
        cleaned, invisible, _ = strip_invisibles(text)
        cleaned, removed = strip_active_content(cleaned)
        for label, count in (("invisible characters", invisible), ("active content", removed)):
            if count:
                ctx.g2_removed[label] = ctx.g2_removed.get(label, 0) + count
        if removed and verdict == Verdict.PASS:
            verdict, reason = Verdict.SANITIZE, "Active content removed"
        ctx.g2_verdict    = verdict
        ctx.g2_confidence = confidence
        ctx.g2_reasoning  = reason
        ctx.g2_latency_ms = (time.perf_counter() - t_start) * 1000
        ctx.final_output  = cleaned
        self._stats["sanitized" if verdict == Verdict.SANITIZE else "passed"] += 1
        if ctx.session:
            ctx.session.response_count += 1
        self._emit(session_id, {
            "event": "verdict", "gateway": "G2", "verdict": verdict.value,
            "confidence": round(confidence, 3), "latency_ms": round(ctx.g2_latency_ms, 1),
        })
        logger.debug(f"G2 [{ctx.request_id[:8]}]: {verdict.value} {ctx.g2_latency_ms:.1f}ms")
        return ctx

    def _basic_sanitize(self, output: str, ctx: RequestContext = None) -> str:
        import re
        for pattern in [
            r"(?i)(my system prompt|my initial instructions?|i was instructed to)[^.]*\.",
            r"(?i)(i have been|i am) (configured|programmed|told)[^.]*\.",
        ]:
            output, hits = re.subn(pattern, "[redacted]", output)
            if hits and ctx is not None:
                ctx.g2_removed["setup disclosure"] = ctx.g2_removed.get("setup disclosure", 0) + hits
        output, notes = redact(output, ctx.raw_input if ctx else "")
        output, removed = strip_active_content(output)
        if ctx is not None:
            for note in notes:
                ctx.g2_removed[note.label] = ctx.g2_removed.get(note.label, 0) + note.count
            if removed:
                ctx.g2_removed["active content"] = ctx.g2_removed.get("active content", 0) + removed
        return output.strip()

    @property
    def stats(self) -> dict:
        t = self._stats["total"]
        return {
            **self._stats,
            "block_rate":    round(self._stats["blocked"]   / t, 3) if t else 0,
            "sanitize_rate": round(self._stats["sanitized"] / t, 3) if t else 0,
        }