"""
HEIMDALL Gateway 1: input sentinel.

Order: canonicalize, L0 cache, L2 sanitize, L1 patterns, L3 + L4 + trajectory, arbiter.
Canonicalizing first means cache keys and every later layer see the same de-obfuscated
text, and a cached PASS can never skip multi-turn analysis.
"""
from __future__ import annotations
from config.settings import get_settings
import asyncio
import time
from typing import Optional
from loguru import logger

from core.models import (
    RequestContext, Verdict, Flag, FlagSource, AttackFamily, SessionState
)
from core.cache.manager import CacheManager
from core.agentic.decision_layer import AgenticDecisionLayer
from core.stream_manager import stream_manager
from .l1_pattern_engine import PatternEngine, run_l1
from .l2_sanitizer import Sanitizer, run_l2
from .canonicalizer import CanonicalResult, canonicalize
from .l3_ml_classifier import MLClassifier, run_l3
from .l4_intent_engine import IntentEngine, run_l4


class InputSentinel:

    def __init__(self,
                 cache:    CacheManager,
                 agentic:  AgenticDecisionLayer,
                 pattern:  PatternEngine,
                 sanitizer: Sanitizer,
                 ml:       MLClassifier,
                 intent:   IntentEngine,
                 trajectory: "TrajectoryMonitor" = None):
        self.cache     = cache
        self.agentic   = agentic
        self.pattern   = pattern
        self.sanitizer = sanitizer
        self.ml        = ml
        self.intent    = intent
        self.trajectory = trajectory
        self._stats    = {"total": 0, "blocked": 0, "sanitized": 0,
                          "passed": 0, "cache_hits": 0}

    # ── SSE emit helper ───────────────────────────────────────────────────────

    def _emit(self, session_id: Optional[str], event: dict) -> None:
        """Push a layer event to the SSE queue (no-op if no session_id)."""
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
        Process a request through the G1 input security pipeline.

        Args:
            ctx:         The request context to process.
            session_id:  SSE session ID for streaming events (optional).
            skip_layers: [RESEARCH ONLY] Set of layer names to bypass for
                         ablation studies. NOT available on production /chat endpoint.
                         Example: frozenset({"L1_PATTERN", "L3_ML"})
        """
        skip_layers = skip_layers or frozenset()
        t_start = time.perf_counter()
        if not ctx.is_immune_probe:
            self._stats["total"] += 1

        flags_before = ctx.flag_count

        # ── L0: Cache lookup ──────────────────────────────────────────────────
        if "L2_SANITIZE" in skip_layers:
            ctx.canonical_result = CanonicalResult(ctx.raw_input, ctx.raw_input, ctx.raw_input)
        else:
            ctx.canonical_result = canonicalize(ctx.raw_input)
        ctx.llm_safe_input = ctx.canonical_result.llm_safe
        cache_key = ctx.canonical_result.canonical

        t_l0 = time.perf_counter()
        cache_result = self.cache.check(cache_key, policy=ctx.policy)
        l0_ms = (time.perf_counter() - t_l0) * 1000

        if cache_result["hit"] and cache_result["tier"] == 0:
            if cache_result.get("verdict") == "PASS":
                # A cached PASS skips per-prompt analysis only; the conversation
                # trajectory is session state and must still be evaluated.
                if self.trajectory and ctx.session:
                    await asyncio.get_running_loop().run_in_executor(None, self.trajectory.run, ctx)
                if ctx.flag_count:
                    return await self._decide(ctx, session_id, skip_layers, t_start, cache_key)
                # Cached PASS verdict
                ctx.g1_verdict    = Verdict.PASS
                ctx.g1_confidence = 0.95
                ctx.g1_reasoning  = "Exact cache match: PASS"
                ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000
                if not ctx.is_immune_probe:
                    self._stats["passed"] += 1
                    self._stats["cache_hits"] += 1
                
                self._emit(session_id, {
                    "event": "layer", "gateway": "G1", "layer": "L0",
                    "name": "Attack Cache", "status": "PASS",
                    "latency_ms": round(l0_ms, 2), "flags": ctx.flag_count,
                    "detail": "Tier-0 exact hash match (PASS)",
                })
                self._emit(session_id, {
                    "event": "verdict", "gateway": "G1",
                    "verdict": "PASS", "confidence": 0.95,
                    "latency_ms": round(ctx.g1_latency_ms, 1),
                })
                logger.info(f"G1 [{ctx.request_id[:8]}]: PASS (L0 cache hit) {ctx.g1_latency_ms:.1f}ms")
                return ctx
            
            # Tier-0 exact match → immediate block
            ctx.g1_verdict    = Verdict.BLOCK
            ctx.g1_confidence = 1.0
            ctx.g1_reasoning  = f"Exact cache match: {cache_result.get('family','KNOWN_ATTACK')}"
            ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000
            if not ctx.is_immune_probe:
                self._stats["blocked"] += 1
                self._stats["cache_hits"] += 1

            self._emit(session_id, {
                "event": "layer", "gateway": "G1", "layer": "L0",
                "name": "Attack Cache", "status": "BLOCK",
                "latency_ms": round(l0_ms, 2), "flags": ctx.flag_count,
                "detail": "Tier-0 exact hash match",
            })
            self._emit(session_id, {
                "event": "verdict", "gateway": "G1",
                "verdict": "BLOCK", "confidence": 1.0,
                "attack_type": cache_result.get("family", "KNOWN_ATTACK"),
                "latency_ms": round(ctx.g1_latency_ms, 1),
            })
            logger.info(f"G1 [{ctx.request_id[:8]}]: BLOCK (L0 cache hit) {ctx.g1_latency_ms:.1f}ms")
            return ctx

        # Warm cache flag
        cache_status = "MISS"
        if cache_result.get("flag"):
            sim  = cache_result.get("similarity", 0.0)
            fam  = cache_result.get("family", "UNKNOWN")
            sev  = cache_result.get("severity", 7)
            try:
                family = AttackFamily(fam)
            except ValueError:
                family = AttackFamily.UNKNOWN
            ctx.add_flag(Flag(
                source=FlagSource.CACHE,
                severity=sev,
                confidence=sim,
                attack_families=[family],
                evidence=f"Warm cache similarity={sim:.3f} family={fam}",
                cache_proximity=sim,
            ))
            cache_status = "FLAG"

        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L0",
            "name": "Attack Cache", "status": cache_status,
            "latency_ms": round(l0_ms, 2), "flags": ctx.flag_count,
        })

        # ── L1 + L2: Pattern scan + Sanitize (parallel) ───────────────────────
        t_l12 = time.perf_counter()
        loop  = asyncio.get_running_loop()
        flags_before_l12 = ctx.flag_count

        if "L2_SANITIZE" not in skip_layers:
            await loop.run_in_executor(None, _run_l2_sync, ctx, self.sanitizer)
        if "L1_PATTERN" not in skip_layers:
            await loop.run_in_executor(None, run_l1, ctx, self.pattern)
        l12_ms = (time.perf_counter() - t_l12) * 1000

        new_flags_l1 = ctx.flag_count - flags_before_l12
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L1",
            "name": "Pattern Engine",
            "status": "DISABLED" if "L1_PATTERN" in skip_layers else ("FLAG" if new_flags_l1 > 0 else "PASS"),
            "latency_ms": round(l12_ms, 2),
            "flags": ctx.flag_count,
            "new_flags": new_flags_l1,
        })
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L2",
            "name": "Token Sanitizer",
            "status": "DISABLED" if "L2_SANITIZE" in skip_layers else ("SANITIZED" if ctx.normalization_delta > 0 else "PASS"),
            "latency_ms": round(l12_ms, 2),
            "flags": ctx.flag_count,
            "transforms": ctx.normalization_delta,
        })

        # ── L3 + L4: ML Classifier + Intent Engine (parallel) ─────────────────
        t_l34 = time.perf_counter()
        flags_before_l34 = ctx.flag_count

        tasks_l34 = []
        if "L3_ML" not in skip_layers:
            tasks_l34.append(loop.run_in_executor(None, run_l3, ctx, self.ml))
        if "L4_INTENT" not in skip_layers:
            tasks_l34.append(loop.run_in_executor(None, run_l4, ctx, self.intent))
        
        def run_traj():
            if self.trajectory:
                self.trajectory.run(ctx)
                
        tasks_l34.append(loop.run_in_executor(None, run_traj))
        await asyncio.gather(*tasks_l34)
        l34_ms = (time.perf_counter() - t_l34) * 1000

        new_flags_l34 = ctx.flag_count - flags_before_l34
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L3",
            "name": "ML Classifier",
            "status": "DISABLED" if "L3_ML" in skip_layers else ("FLAG" if new_flags_l34 > 0 else "PASS"),
            "latency_ms": round(l34_ms, 2),
            "flags": ctx.flag_count,
        })
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L4",
            "name": "Intent Engine",
            "status": "DISABLED" if "L4_INTENT" in skip_layers else ("FLAG" if new_flags_l34 > 0 else "PASS"),
            "latency_ms": round(l34_ms, 2),
            "flags": ctx.flag_count,
        })

        return await self._decide(ctx, session_id, skip_layers, t_start, cache_key)

    async def _decide(self, ctx, session_id, skip_layers, t_start, cache_key) -> RequestContext:
        # ── No flags: clean pass ──────────────────────────────────────────────
        if ctx.flag_count == 0:
            ctx.g1_verdict    = Verdict.PASS
            ctx.g1_confidence = 0.95
            ctx.g1_reasoning  = "No flags raised by any detection layer"
            ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000
            if not ctx.is_immune_probe:
                self._stats["passed"] += 1
                self.cache.store_pass(cache_key, policy=ctx.policy)
            if ctx.session:
                ctx.session.record_clean()
            self._emit(session_id, {
                "event": "verdict", "gateway": "G1", "verdict": "PASS",
                "confidence": 0.95, "latency_ms": round(ctx.g1_latency_ms, 1),
            })
            logger.debug(f"G1 [{ctx.request_id[:8]}]: PASS (clean) {ctx.g1_latency_ms:.1f}ms")
            return ctx

        # ── Soft flags outside the arbiter sample: forward, spotlighted ───────
        if not ctx.should_escalate_to_agentic:
            return self._soft_pass(ctx, session_id, t_start, "flags below arbiter threshold")

        # ── L5: Agentic Decision Layer ────────────────────────────────────────
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L5",
            "name": "Agentic Decision", "status": "RUNNING" if "AGENTIC" not in skip_layers else "DISABLED",
            "latency_ms": 0.0, "flags": ctx.flag_count,
        })
        t_l5 = time.perf_counter()

        if "AGENTIC" not in skip_layers:
            decision = await self.agentic.decide_input(ctx)
        else:
            from core.models import AgenticDecision
            decision = AgenticDecision(
                verdict=Verdict.BLOCK, confidence=0.8, attack_type=AttackFamily.UNKNOWN,
                reason="Agentic layer bypassed (ablation): deterministic fallback blocked",
            )
        l5_ms = (time.perf_counter() - t_l5) * 1000

        from core.models import PipelineStatus
        settings = get_settings()
        arbiter_failed = decision.unavailable or ctx.arbiter_error == "unreadable_reply"

        # Human in the loop: when the arbiter cannot give a verdict, a person does. The request waits
        # (it is never answered meanwhile), so this is at least as safe as blocking, and a false alarm
        # can still be rescued. Corroborated critical evidence is blocked outright: no one need look.
        if arbiter_failed and settings.review_on_arbiter_failure == "review" and "AGENTIC" not in skip_layers:
            ctx.degraded = True
            if not ctx.corroborated_critical:
                return self._hold(ctx, session_id, t_start, l5_ms,
                                  f"Arbiter gave no verdict ({ctx.arbiter_error or 'unavailable'})")

        # Legacy graded fail-closed: an outage blocks hard signals and forwards a lone soft signal spotlighted.
        if decision.unavailable and not ctx.has_hard_flag:
            ctx.degraded = True
            self._emit(session_id, {
                "event": "layer", "gateway": "G1", "layer": "L5", "name": "Agentic Decision",
                "status": "UNAVAILABLE", "latency_ms": round(l5_ms, 2), "flags": ctx.flag_count,
                "reason": "Arbiter unreachable; soft signal forwarded with spotlighting",
            })
            return self._soft_pass(ctx, session_id, t_start, "arbiter unreachable, soft flags only")

        if not (ctx.has_critical_flag and ctx.combined_severity > 25) and not decision.unavailable:
            if 0.40 <= decision.confidence <= 0.60 and not ctx.corroborated_critical:
                ctx.pipeline_status = PipelineStatus.HELD_FOR_REVIEW
                ctx.review_reason = f"Arbiter unsure (confidence {decision.confidence:.2f})"

        # The arbiter reads attacker text, so it may not clear on its own what the fixed layers would
        # block. A disagreement goes to a person (or is blocked, by setting). Found in a live run where
        # the arbiter cleared a base64 extraction request that carried three signals.
        clears = decision.verdict in (Verdict.PASS, Verdict.SANITIZE)
        conflict = settings.arbiter_conflict_action
        if clears and ctx.has_hard_flag and not arbiter_failed and conflict in ("review", "block") \
                and "AGENTIC" not in skip_layers:
            if conflict == "block":
                decision.verdict = Verdict.BLOCK
                decision.reason = f"Arbiter clearance not accepted against a hard signal ({decision.reason[:80]})"
                decision.cache_action = "NONE"
            else:
                decision.cache_action = "NONE"
                return self._hold(ctx, session_id, t_start, l5_ms,
                                  f"Arbiter cleared a request the fixed layers flag as an attack: {decision.reason[:100]}",
                                  confidence=decision.confidence)

        ctx.g1_verdict     = decision.verdict
        ctx.g1_confidence  = decision.confidence
        ctx.g1_reasoning   = decision.reason
        ctx.g1_attack_type = decision.attack_type

        if decision.verdict == Verdict.SANITIZE:
            ctx.sanitized_input = self._vet_sanitized(ctx, decision)
            if ctx.sanitized_input is None:
                ctx.g1_verdict = Verdict.BLOCK
                ctx.g1_reasoning = "Sanitized text still carried an injection signal"

        # The arbiter reads attacker text, so its cache instructions only count
        # when deterministic layers agree this was an attack.
        if decision.attack_confirmed and ctx.has_hard_flag and decision.verdict == Verdict.BLOCK:
            if decision.cache_action in ("ADD_T0", "ADD_T1"):
                self.cache.store_attack(cache_key, decision.attack_type.value, ctx.max_severity,
                                        add_to_hot=decision.cache_action == "ADD_T0", add_to_warm=True,
                                        policy=ctx.policy)

        ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000

        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L5",
            "name": "Agentic Decision",
            "status": ("FALLBACK_DECISION" if "AGENTIC" in skip_layers
                       else "UNAVAILABLE" if decision.unavailable else ctx.g1_verdict.value),
            "latency_ms": round(l5_ms, 2), "flags": ctx.flag_count,
            "confidence": round(decision.confidence, 3), "attack_type": decision.attack_type.value,
            "reason": ctx.g1_reasoning[:120], "tokens_used": decision.tokens_used,
        })
        self._emit(session_id, {
            "event": "verdict", "gateway": "G1", "verdict": ctx.g1_verdict.value,
            "confidence": round(decision.confidence, 3), "attack_type": decision.attack_type.value,
            "flags": ctx.flag_count, "latency_ms": round(ctx.g1_latency_ms, 1),
            "fail_closed": decision.unavailable,
        })

        verdict = ctx.g1_verdict
        if not ctx.is_immune_probe:
            key = {Verdict.BLOCK: "blocked", Verdict.SANITIZE: "sanitized"}.get(verdict, "passed")
            self._stats[key] += 1
        logger.info(f"G1 [{ctx.request_id[:8]}]: {verdict.value} conf={decision.confidence:.2f} "
                    f"flags={ctx.flag_count} latency={ctx.g1_latency_ms:.0f}ms tokens={ctx.agentic_tokens_used}")
        return ctx

    def _hold(self, ctx, session_id, t_start, l5_ms, reason: str, confidence: float = 0.5) -> RequestContext:
        """Wait for a person. The verdict stays BLOCK, so any caller that does not handle holds fails closed."""
        from core.models import PipelineStatus
        ctx.pipeline_status = PipelineStatus.HELD_FOR_REVIEW
        ctx.review_reason = reason
        ctx.g1_verdict = Verdict.BLOCK
        ctx.g1_confidence = confidence
        ctx.g1_reasoning = reason
        ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000
        if not ctx.is_immune_probe:
            self._stats["held"] = self._stats.get("held", 0) + 1
        self._emit(session_id, {
            "event": "layer", "gateway": "G1", "layer": "L5", "name": "Agentic Decision",
            "status": "HELD_FOR_REVIEW", "latency_ms": round(l5_ms, 2), "flags": ctx.flag_count, "reason": reason[:120],
        })
        logger.info(f"G1 [{ctx.request_id[:8]}]: HELD for review ({reason[:60]})")
        return ctx

    def _soft_pass(self, ctx, session_id, t_start, detail: str) -> RequestContext:
        ctx.g1_verdict    = Verdict.PASS
        ctx.g1_confidence = 0.6
        ctx.g1_reasoning  = f"Low-severity flags ({ctx.flag_count}): {detail}"
        ctx.g1_latency_ms = (time.perf_counter() - t_start) * 1000
        ctx.spotlighted   = True
        if not ctx.is_immune_probe:
            self._stats["passed"] += 1
        self._emit(session_id, {
            "event": "verdict", "gateway": "G1", "verdict": "PASS", "confidence": 0.6,
            "detail": detail, "flags": ctx.flag_count, "latency_ms": round(ctx.g1_latency_ms, 1),
        })
        return ctx

    def _vet_sanitized(self, ctx: RequestContext, decision) -> Optional[str]:
        """The arbiter's rewrite is model output too. Re-scan it before trusting it."""
        candidate = decision.sanitized_input
        if not candidate:
            return ctx.llm_safe_input  # no rewrite supplied: forward normalized text, spotlighted
        check = RequestContext(raw_input=candidate, policy=ctx.policy)
        run_l2(check, self.sanitizer)
        run_l1(check, self.pattern)
        if check.has_hard_flag:
            return None
        return check.llm_safe_input

    def input_for_llm(self, ctx: RequestContext) -> str:
        """Text sent to the model: normalized, never the raw bytes the detectors saw through."""
        if ctx.g1_verdict == Verdict.BLOCK:
            raise RuntimeError("Attempted to get LLM input for a BLOCK verdict")
        if ctx.g1_verdict == Verdict.SANITIZE and ctx.sanitized_input:
            return ctx.sanitized_input
        return ctx.llm_safe_input or ctx.raw_input

    @property
    def stats(self) -> dict:
        t = self._stats["total"]
        return {
            **self._stats,
            "block_rate":     round(self._stats["blocked"]    / t, 3) if t else 0,
            "sanitize_rate":  round(self._stats["sanitized"]  / t, 3) if t else 0,
            "cache_hit_rate": round(self._stats["cache_hits"] / t, 3) if t else 0,
        }


def _run_l2_sync(ctx: RequestContext, sanitizer: Sanitizer) -> None:
    from .l2_sanitizer import run_l2
    run_l2(ctx, sanitizer)
