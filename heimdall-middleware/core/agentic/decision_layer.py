"""
GUARDIAN v2 — Agentic Decision Layer
The final authority for both Gateway 1 (input) and Gateway 2 (output).
Only activates when lower layers raise flags. ~300 input / ~80 output tokens.
"""
from __future__ import annotations
import json
import re
import time
from loguru import logger

from config.settings import get_settings
from core.models import AgenticDecision, RequestContext, Verdict
from core.llm_clients import LLMClientPool
from .prompts import (
    INPUT_SYSTEM_PROMPT, OUTPUT_SYSTEM_PROMPT,
    build_input_dossier, build_output_dossier,
)


class AgenticDecisionLayer:
    """
    Single instance shared by both gateways.
    Gateway 1 calls decide_input(); Gateway 2 calls decide_output().
    """

    def __init__(self, client_pool: LLMClientPool):
        self._pool  = client_pool
        self._stats = {"input_calls": 0, "output_calls": 0,
                       "blocks": 0, "sanitizes": 0, "passes": 0,
                       "total_tokens": 0, "errors": 0, "unreadable": 0}

    # ── Gateway 1 ─────────────────────────────────────────────────────────────

    async def decide_input(self, ctx: RequestContext) -> AgenticDecision:
        """Return the final input verdict. Any failure resolves to BLOCK or degrades by severity."""
        self._stats["input_calls"] += 1

        # Critical and overwhelming evidence never needs a model call.
        if ctx.has_critical_flag and ctx.combined_severity > 25:
            logger.warning(f"Agentic [{ctx.request_id[:8]}]: auto-BLOCK (critical flags)")
            self._stats["blocks"] += 1
            return AgenticDecision.safe_block("Multiple critical-severity injection signals detected")

        decision = await self._ask(ctx, build_input_dossier(ctx), INPUT_SYSTEM_PROMPT, "INPUT")
        if decision.verdict != Verdict.BLOCK and ctx.corroborated_critical:
            # The arbiter reads attacker text and may have been talked round. It can
            # resolve ambiguity, but it cannot clear corroborated critical evidence.
            logger.warning(f"Agentic [{ctx.request_id[:8]}]: arbiter {decision.verdict.value} overruled by corroborated evidence")
            decision.verdict = Verdict.BLOCK
            decision.reason = "Corroborated critical evidence; arbiter clearance not accepted"
            decision.cache_action = "NONE"
            decision.confidence = max(decision.confidence, 0.85)
        self._record_verdict(decision.verdict)
        return decision

    # ── Gateway 2 ─────────────────────────────────────────────────────────────

    async def decide_output(self, ctx: RequestContext, leakage_score: float = 0.0,
                            pii_detected: bool = False, drift_score: float = 0.0,
                            baseline_turns: int = 0, flags=None) -> AgenticDecision:
        self._stats["output_calls"] += 1
        dossier = build_output_dossier(ctx, leakage_score=leakage_score, pii_detected=pii_detected,
                                       drift_score=drift_score, baseline_turns=baseline_turns, flags=flags)
        decision = await self._ask(ctx, dossier, OUTPUT_SYSTEM_PROMPT, "OUTPUT")
        decision.cache_action = "NONE"
        self._record_verdict(decision.verdict)
        return decision

    async def _ask(self, ctx: RequestContext, dossier: str, system: str, label: str) -> AgenticDecision:
        started = time.perf_counter()
        resp = await self._pool.complete_agentic(prompt=dossier, system=system,
                                                 max_tokens=get_settings().agentic_max_tokens)
        if not resp.ok:
            self._stats["errors"] += 1
            logger.warning(f"Agentic {label} [{ctx.request_id[:8]}]: unavailable ({resp.error}); failing closed")
            reason = ("Agentic decision layer unavailable (circuit breaker open)"
                      if resp.error == "agentic_breaker_open" else "AGENTIC_ERROR_FAIL_CLOSED")
            decision = AgenticDecision.safe_block(reason)
            decision.unavailable = True
            ctx.arbiter_error = resp.error or "unavailable"
            return decision
        tokens = resp.tokens_input + resp.tokens_output
        decision = self._parse_response(resp.text, tokens)
        ctx.agentic_tokens_used += tokens
        if decision.reason == "AGENTIC_ERROR_FAIL_CLOSED":
            # The arbiter answered but its reply could not be read. Still a block (it may have been
            # manipulated), but it is an arbiter failure, not an arbiter verdict, and is reported as one.
            self._stats["unreadable"] += 1
            ctx.arbiter_error = "unreadable_reply"
            logger.warning(f"Agentic {label} [{ctx.request_id[:8]}]: unreadable reply ({tokens} tokens); failing closed")
        self._stats["total_tokens"] += tokens
        logger.info(f"Agentic {label} [{ctx.request_id[:8]}]: {decision.verdict.value} "
                    f"conf={decision.confidence:.2f} tokens={tokens} "
                    f"latency={(time.perf_counter() - started) * 1000:.0f}ms")
        return decision

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_response(self, text: str, tokens: int) -> AgenticDecision:
        """Accept one JSON object only. A reply carrying several objects is treated as manipulated."""
        cleaned = re.sub(r"```(?:json)?", "", text).strip()
        start = cleaned.find("{")
        if start < 0:
            logger.warning("Agentic: no JSON in response")
            return AgenticDecision.safe_block("AGENTIC_ERROR_FAIL_CLOSED")
        candidate = re.sub(r",\s*([}\]])", r"\1", cleaned[start:])
        decoder = json.JSONDecoder()
        try:
            data, end = decoder.raw_decode(candidate)
        except json.JSONDecodeError:
            logger.warning("Agentic: JSON parse error")
            return AgenticDecision.safe_block("AGENTIC_ERROR_FAIL_CLOSED")
        if not isinstance(data, dict) or "{" in candidate[end:]:
            logger.warning("Agentic: response was not a single JSON object")
            return AgenticDecision.safe_block("AGENTIC_ERROR_FAIL_CLOSED")
        decision = AgenticDecision.from_dict(data)
        decision.tokens_used = tokens
        return decision

    def _record_verdict(self, verdict: Verdict) -> None:
        if verdict == Verdict.BLOCK:
            self._stats["blocks"] += 1
        elif verdict == Verdict.SANITIZE:
            self._stats["sanitizes"] += 1
        else:
            self._stats["passes"] += 1

    @property
    def stats(self) -> dict:
        total = self._stats["input_calls"] + self._stats["output_calls"]
        return {
            **self._stats,
            "avg_tokens_per_call": (
                round(self._stats["total_tokens"] / total, 1) if total else 0
            ),
        }
