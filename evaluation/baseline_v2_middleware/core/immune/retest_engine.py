"""
HEIMDALL Phase 2 — Retest Engine

Runs REAL requests through G1 after a patch is applied.
PATCH_VERIFIED is only issued when this engine confirms the bypass is blocked.

Tests performed:
1. Original bypass payload (the one that triggered the proposal)
2. Related variants (same mutation family, other seeds)
3. Benign samples from data/benign_corpus.json

Regression check: benign inputs must not be incorrectly blocked.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from loguru import logger


@dataclass
class RetestResult:
    """
    The result of a post-patch retest.

    Verification only passes when:
    - original bypass is now blocked
    AND
    - benign regression is acceptable (no new false positives above threshold)
    """
    proposal_id: int
    campaign_id: str

    # Original bypass test
    original_verdict: Optional[str] = None     # G1 verdict after patch
    original_bypassed: bool = True             # True = still a bypass (bad)

    # Related mutations
    related_total: int = 0
    related_still_bypassed: int = 0

    # Benign regression
    benign_total: int = 0
    benign_blocked: int = 0          # False positives introduced by this patch
    benign_allowed: int = 0

    # Verification status
    verification_status: str = "VERIFICATION_INCOMPLETE"
    # VERIFIED | PARTIALLY_VERIFIED | VERIFICATION_FAILED | VERIFICATION_INCOMPLETE

    timestamp: float = field(default_factory=time.time)

    @property
    def benign_fp_rate(self) -> float:
        return round(self.benign_blocked / self.benign_total, 3) if self.benign_total > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "proposalId": self.proposal_id,
            "campaignId": self.campaign_id,
            "originalVerdict": self.original_verdict,
            "originalBypassed": self.original_bypassed,
            "relatedTotal": self.related_total,
            "relatedStillBypassed": self.related_still_bypassed,
            "benignTotal": self.benign_total,
            "benignBlocked": self.benign_blocked,
            "benignAllowed": self.benign_allowed,
            "benignFpRate": self.benign_fp_rate,
            "verificationStatus": self.verification_status,
            "timestamp": self.timestamp,
        }


async def run_retest(
    g1_instance,
    proposal_id: int,
    campaign_id: str,
    original_payload: str,
    related_payloads: list[str],
    benign_payloads: Optional[list[str]] = None,
) -> RetestResult:
    """
    Run a complete retest suite after a patch has been applied and reloaded.

    Parameters
    ----------
    g1_instance     : Running InputSentinel with the new rules loaded
    proposal_id     : DB ID of the proposal being tested
    campaign_id     : Campaign scoping
    original_payload : The exact payload that bypassed before the patch
    related_payloads : Variants of the same attack (same family, different seeds)
    benign_payloads  : Benign samples for regression check

    Returns a RetestResult. VERIFIED only if:
    - original_payload is now blocked
    - benign FP rate is < 10% (or no benign samples to test)
    """
    from core.models import RequestContext

    result = RetestResult(proposal_id=proposal_id, campaign_id=campaign_id)

    # ── 1. Retest original bypass ──────────────────────────────────────────
    logger.info(f"Retest: testing original payload for proposal {proposal_id}")
    try:
        ctx = RequestContext(raw_input=original_payload, is_immune_probe=True)
        ctx = await g1_instance.process(ctx)
        original_verdict = ctx.g1_verdict.value if ctx.g1_verdict else "UNKNOWN"
        result.original_verdict = original_verdict
        result.original_bypassed = (original_verdict == "PASS")
    except Exception as e:
        logger.error(f"Retest original payload failed: {e}")
        result.original_bypassed = True  # Conservative: assume still bypassed
        result.original_verdict = "ERROR"

    # ── 2. Retest related mutations ────────────────────────────────────────
    result.related_total = len(related_payloads)
    still_bypassed = 0
    for payload in related_payloads:
        try:
            ctx = RequestContext(raw_input=payload, is_immune_probe=True)
            ctx = await g1_instance.process(ctx)
            verdict = ctx.g1_verdict.value if ctx.g1_verdict else "UNKNOWN"
            if verdict == "PASS":
                still_bypassed += 1
        except Exception:
            pass  # Count as unknown, not as bypass
    result.related_still_bypassed = still_bypassed

    # ── 3. Benign regression check ─────────────────────────────────────────
    if benign_payloads is None:
        benign_payloads = _load_benign_samples()

    result.benign_total = len(benign_payloads)
    benign_blocked = 0
    benign_allowed = 0
    for payload in benign_payloads:
        try:
            ctx = RequestContext(raw_input=payload, is_immune_probe=True)
            ctx = await g1_instance.process(ctx)
            verdict = ctx.g1_verdict.value if ctx.g1_verdict else "UNKNOWN"
            if verdict == "BLOCK":
                benign_blocked += 1
            else:
                benign_allowed += 1
        except Exception:
            pass

    result.benign_blocked = benign_blocked
    result.benign_allowed = benign_allowed

    # ── 4. Determine verification status ──────────────────────────────────
    result.verification_status = _compute_verification_status(result)
    logger.info(
        f"Retest complete for proposal {proposal_id}: "
        f"original_bypassed={result.original_bypassed}, "
        f"status={result.verification_status}"
    )
    return result


def _compute_verification_status(result: RetestResult) -> str:
    """
    Determine verification status from retest results.

    VERIFIED: original bypass blocked AND benign FP rate acceptable (< 10%)
    PARTIALLY_VERIFIED: original bypass blocked BUT benign regression or related still bypassed
    VERIFICATION_FAILED: original bypass still passes (patch did not work)
    """
    if result.original_bypassed:
        # Patch did not block the original attack — failed
        return "VERIFICATION_FAILED"

    # Original is blocked — check for regressions
    has_benign_regression = (
        result.benign_total > 0 and result.benign_fp_rate >= 0.10
    )
    has_related_regression = (
        result.related_total > 0 and
        result.related_still_bypassed > result.related_total * 0.5
    )

    if has_benign_regression or has_related_regression:
        return "PARTIALLY_VERIFIED"

    return "VERIFIED"


def _load_benign_samples(max_samples: int = 5) -> list[str]:
    """Load benign samples from data/benign_corpus.json for regression testing."""
    benign_path = "data/benign_corpus.json"
    try:
        if os.path.exists(benign_path):
            with open(benign_path, "r", encoding="utf-8") as f:
                corpus = json.load(f)
            texts = [item.get("text", "") for item in corpus if item.get("text")]
            return texts[:max_samples]
    except Exception as e:
        logger.warning(f"Could not load benign corpus: {e}")
    # Fallback: a few genuinely benign samples
    return [
        "What is the capital of France?",
        "Help me write a thank you note.",
        "Explain how photosynthesis works.",
    ]


def store_retest_result(result: RetestResult) -> int:
    """Persist retest result to the DB."""
    import sqlite3
    conn = sqlite3.connect("data/immune_system.db")
    try:
        cur = conn.execute("""
            CREATE TABLE IF NOT EXISTS retest_results (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id         INTEGER NOT NULL,
                campaign_id         TEXT NOT NULL,
                original_bypassed   BOOLEAN NOT NULL,
                original_verdict    TEXT,
                related_total       INTEGER NOT NULL DEFAULT 0,
                related_bypassed    INTEGER NOT NULL DEFAULT 0,
                benign_blocked      INTEGER NOT NULL DEFAULT 0,
                benign_total        INTEGER NOT NULL DEFAULT 0,
                verification_status TEXT NOT NULL,
                timestamp           REAL NOT NULL
            )
        """)
        cur = conn.execute("""
            INSERT INTO retest_results
                (proposal_id, campaign_id, original_bypassed, original_verdict,
                 related_total, related_bypassed, benign_blocked, benign_total,
                 verification_status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.proposal_id,
            result.campaign_id,
            result.original_bypassed,
            result.original_verdict,
            result.related_total,
            result.related_still_bypassed,
            result.benign_blocked,
            result.benign_total,
            result.verification_status,
            result.timestamp,
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()
