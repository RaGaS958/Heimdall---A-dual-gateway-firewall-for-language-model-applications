"""
HEIMDALL Phase 2 — Immune System API

Endpoints:
  POST /immune/campaign                    — start a new campaign (static or adaptive)
  GET  /immune/campaign/{id}               — get campaign state
  GET  /immune/campaign/{id}/vulnerabilities — get vulnerability clusters
  GET  /immune/stream                      — SSE stream of campaign events
  GET  /immune/coverage                    — mutation coverage matrix
  GET  /immune/proposals                   — pending patch proposals
  POST /immune/proposals/{id}/approve      — approve + apply + REAL retest + REAL verify
  POST /immune/proposals/{id}/reject       — reject (no rule change)
  GET  /immune/memory                      — security memory records
  GET  /immune/history                     — past campaign history

Human approval boundary:
  AI proposes → HUMAN approves/rejects → system applies → real retest → real verify.
  PATCH_VERIFIED is never emitted without a confirmed retest result.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import yaml
from fastapi import APIRouter, HTTPException, BackgroundTasks, Header, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional
import os

from core.immune.campaign_runner import (
    DB_PATH, init_db, run_campaign, CampaignConfig,
    get_campaign_history, get_campaign_vulnerabilities,
    get_campaign_state, is_campaign_active, get_active_campaign_id,
    _bypass_payloads_registry,
)
from core.immune.events import immune_events
from core.security.errors import api_error
from core.immune.patch_engine import (
    apply_patch, update_proposal_state, get_defense_version,
    increment_defense_version, is_proposal_stale,
    PatchState, PatchProposal,
    restore_rules,
    snapshot_rules,
)
from core.immune.retest_engine import run_retest, store_retest_result
from core.immune.security_memory import get_all_records, update_patch_status
from core.immune.vulnerability_model import cluster_bypasses, VulnerabilityRecord

router = APIRouter(prefix="/immune", tags=["immune"])

# ── Request Schemas ────────────────────────────────────────────────────────────

class CampaignRequest(BaseModel):
    seed_ids: List[str]
    techniques: List[str]
    n_per_technique: int = 1
    mode: str = Field(default="static", pattern="^(static|adaptive)$")
    max_attempts: int = Field(default=36, ge=1, le=200)
    max_rounds: int = Field(default=3, ge=1, le=10)
    max_patch_proposals: int = Field(default=10, ge=1, le=20)
    timeout: float = Field(default=300.0, ge=10.0, le=600.0)
    exploration_ratio: float = Field(default=0.3, ge=0.0, le=1.0)
    seed: Optional[int] = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_db():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


_g1_instance = None


def set_g1(g1):
    global _g1_instance
    _g1_instance = g1


from core.security.auth import create_admin_stream_token, verify_admin, verify_admin_stream_token


_approval_lock = asyncio.Lock()


@router.post("/stream-token")
async def immune_stream_token(x_admin_key: str = Header(default="")):
    """EventSource cannot send headers, so the console trades its key for a short token."""
    verify_admin(x_admin_key)
    return {"token": create_admin_stream_token()}


# ── SSE Stream ────────────────────────────────────────────────────────────────

@router.get("/stream")
async def sse_stream(request: Request, token: str = ""):
    """
    Server-Sent Events stream for immune campaign events.
    All events include campaignId — frontend filters by active campaign.
    """
    if not verify_admin_stream_token(token):
        raise HTTPException(status_code=403, detail="Invalid or expired stream token")
    q = immune_events.subscribe()

    async def event_generator():
        yield ": connected\n\n"  # sends headers now, so the browser knows the stream is open
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=5.0)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat ping
                    yield f"data: {json.dumps({'type': 'PING', 'campaignId': ''})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            immune_events.unsubscribe(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Campaign Endpoints ────────────────────────────────────────────────────────

@router.post("/campaign")
async def start_campaign(
    req: CampaignRequest,
    background_tasks: BackgroundTasks,
    x_admin_key: str = Header(default=""),
):
    verify_admin(x_admin_key)
    if not _g1_instance:
        raise HTTPException(status_code=500, detail="G1 not initialized")

    # Prevent concurrent campaigns
    if is_campaign_active():
        raise HTTPException(
            status_code=409,
            detail=f"Campaign {get_active_campaign_id()} is already active. Wait for it to complete or cancel it."
        )

    # Validate techniques
    from core.immune.mutation_engine import MUTATION_TAXONOMY
    invalid = [t for t in req.techniques if t not in MUTATION_TAXONOMY and t != "llm_paraphrase"]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown techniques: {invalid}")

    config = CampaignConfig(
        seed_ids=req.seed_ids,
        techniques=req.techniques,
        n_per_technique=req.n_per_technique,
        mode=req.mode,
        max_attempts=req.max_attempts,
        max_rounds=req.max_rounds,
        max_patch_proposals=req.max_patch_proposals,
        timeout=req.timeout,
        exploration_ratio=req.exploration_ratio,
        seed=req.seed,
    )

    background_tasks.add_task(run_campaign, _g1_instance, config)

    return {
        "status": "started",
        "campaignId": config.campaign_id,
        "mode": config.mode,
        "techniques": req.techniques,
        "seeds": len(req.seed_ids),
        "maxAttempts": req.max_attempts,
        "seed": req.seed,
    }


@router.get("/campaign/{campaign_id}")
async def get_campaign(campaign_id: str, x_admin_key: str = Header(default="")):
    verify_admin(x_admin_key)
    state = get_campaign_state(campaign_id)
    if not state:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return state


@router.get("/campaign/{campaign_id}/vulnerabilities")
async def get_vulnerabilities(campaign_id: str, x_admin_key: str = Header(default="")):
    verify_admin(x_admin_key)
    clusters = get_campaign_vulnerabilities(campaign_id)
    return {"campaignId": campaign_id, "clusters": clusters}


# ── Coverage ──────────────────────────────────────────────────────────────────

@router.get("/coverage")
async def get_coverage(x_admin_key: str = Header(default="")):
    verify_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT seed_id, technique,
               COUNT(*) as total,
               SUM(CASE WHEN bypassed=1 THEN 1 ELSE 0 END) as bypassed
        FROM mutations
        GROUP BY seed_id, technique
    """)
    rows = c.fetchall()
    conn.close()

    matrix = {}
    for r in rows:
        seed = r["seed_id"]
        tech = r["technique"]
        total = r["total"] or 0
        bypassed = r["bypassed"] or 0
        rate = round(bypassed / total, 2) if total > 0 else 0.0

        if seed not in matrix:
            matrix[seed] = {}
        matrix[seed][tech] = {
            "attempts": total,
            "bypasses": bypassed,
            "bypass_rate": rate,
        }

    return {"coverage": matrix}


# ── Proposals ─────────────────────────────────────────────────────────────────

@router.get("/proposals")
async def list_proposals(x_admin_key: str = Header(default="")):
    verify_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM proposals WHERE status = "PENDING" ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    proposals = []
    for r in rows:
        p = dict(r)
        # Parse fix_data for frontend
        try:
            p["proposed_fix_data_parsed"] = json.loads(p.get("proposed_fix_data", "{}"))
        except Exception:
            p["proposed_fix_data_parsed"] = {}
        # Check staleness
        defense_ver = p.get("defense_version") or 1
        p["is_stale"] = is_proposal_stale(defense_ver)
        p["current_defense_version"] = get_defense_version()
        # The payload itself stays server-side; the page only needs to know it exists.
        p["retestable"] = bool(p.pop("bypass_payload", None) or _bypass_payloads_registry.get(str(p.get("id"))))
        proposals.append(p)

    return {"proposals": proposals}


@router.get("/proposals/{proposal_id}")
async def get_proposal(proposal_id: int, x_admin_key: str = Header(default="")):
    """State of one proposal, with its latest retest once the workflow has finished."""
    verify_admin(x_admin_key)
    conn = get_db()
    try:
        row = conn.execute("SELECT id, proposal_id, status, proposal_state, campaign_id, seed_id, technique "
                           "FROM proposals WHERE id = ?", (proposal_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Proposal not found")
        try:
            retest = conn.execute("SELECT * FROM retest_results WHERE proposal_id = ? ORDER BY rowid DESC LIMIT 1",
                                  (proposal_id,)).fetchone()
        except sqlite3.OperationalError:
            retest = None  # The table is created by the first retest.
    finally:
        conn.close()
    return {**dict(row), "retest": dict(retest) if retest else None}


@router.post("/proposals/{proposal_id}/approve")
async def approve_proposal(
    proposal_id: str,
    background_tasks: BackgroundTasks,
    x_admin_key: str = Header(default=""),
):
    """
    HUMAN APPROVAL ENDPOINT.

    Flow:
      1. Verify proposal exists and is PENDING
      2. Check for staleness (defense version mismatch)
      3. Apply patch (PATTERN or KEYWORD)
      4. Reload pattern engine
      5. Run REAL retest through G1
      6. Emit PATCH_VERIFIED only if retest confirms bypass is blocked
      7. Update security memory
    """
    verify_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    row = c.fetchone()
    row = dict(row) if row else None
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Proposal not found")

    if row["status"] not in ("PENDING",):
        raise HTTPException(status_code=400, detail=f"Proposal already processed (status={row['status']})")

    if not _g1_instance:
        raise HTTPException(status_code=500, detail="G1 not initialized")

    stored_payload = _bypass_payloads_registry.get(str(proposal_id)) or row.get("bypass_payload") or ""
    if not stored_payload:
        raise api_error(409, "proposal_not_retestable",
                        "This proposal no longer has the bypass text it was created from, so a fix could not be verified.",
                        "Reject it and run a new campaign. New proposals keep their bypass text.")

    # Build proposal object for patch engine
    try:
        fix_data = json.loads(row["proposed_fix_data"] or "{}")
    except Exception:
        fix_data = {}

    proposal = PatchProposal(
        db_id=proposal_id,
        proposal_id=row.get("proposal_id") or f"P-{proposal_id}",
        campaign_id=row.get("campaign_id") or "",
        seed_id=row.get("seed_id") or "",
        technique=row.get("technique") or "",
        patch_type=row.get("proposed_fix_type") or "PATTERN",
        patch_data=fix_data,
        affected_layer=row.get("affected_layer") or "UNKNOWN",
        explanation_why=row.get("explanation_why") or "",
        explanation_what=row.get("explanation_what") or "",
        explanation_where=row.get("explanation_where") or "",
        explanation_how=row.get("explanation_how") or "",
        explanation_verify=row.get("explanation_verify") or "",
        defense_version_at_creation=row.get("defense_version") or 1,
        state=PatchState.APPROVED,
    )

    # Check staleness
    if is_proposal_stale(proposal.defense_version_at_creation):
        # Still allow approval but warn in events
        await immune_events.publish("PROPOSAL_STALE", {
            "proposalId": proposal_id,
            "proposalDefenseVersion": proposal.defense_version_at_creation,
            "currentDefenseVersion": get_defense_version(),
        }, proposal.campaign_id)

    # Start the async approval workflow as a background task
    background_tasks.add_task(
        _run_approval_workflow,
        proposal=proposal,
        proposal_id=proposal_id,
        original_payload=stored_payload,
    )

    # Immediately mark as APPROVED in DB
    update_proposal_state(proposal_id, PatchState.APPROVED)
    await immune_events.publish("PATCH_APPROVED", {
        "proposalId": proposal_id,
        "proposalPid": proposal.proposal_id,
    }, proposal.campaign_id)

    return {"status": "approved", "proposalId": proposal_id}


async def _run_approval_workflow(proposal: PatchProposal, proposal_id: str, original_payload: str):
    async with _approval_lock:
        await _approve_locked(proposal, proposal_id, original_payload)


async def _approve_locked(proposal: PatchProposal, proposal_id: str, original_payload: str):
    """
    Background task: apply patch → reload → real retest → verify.
    Only emits PATCH_VERIFIED when retest actually confirms the fix.
    """
    cid = proposal.campaign_id

    # ── APPLYING ──────────────────────────────────────────────────────────────
    update_proposal_state(proposal_id, PatchState.APPLYING)
    await immune_events.publish("PATCH_APPLYING", {"proposalId": proposal_id}, cid)

    snapshot = snapshot_rules()
    success, msg = apply_patch(proposal, _g1_instance)
    if not success:
        update_proposal_state(proposal_id, PatchState.APPLY_FAILED)
        await immune_events.publish("PATCH_APPLY_FAILED", {
            "proposalId": proposal_id, "error": msg
        }, cid)
        return

    # ── RELOADING ─────────────────────────────────────────────────────────────
    update_proposal_state(proposal_id, PatchState.RELOADING)
    await immune_events.publish("RULE_RELOADED", {
        "proposalId": proposal_id,
        "patchType": proposal.patch_type,
    }, cid)

    # Increment defense version
    new_defense_version = increment_defense_version(proposal.proposal_id)
    await immune_events.publish("DEFENSE_VERSION_UPDATED", {
        "proposalId": proposal_id,
        "newVersion": new_defense_version,
    }, cid)

    # ── RETESTING ─────────────────────────────────────────────────────────────
    update_proposal_state(proposal_id, PatchState.RETESTING)
    await immune_events.publish("RETEST_STARTED", {"proposalId": proposal_id}, cid)

    # Gather related mutations (same seed, same technique, re-mutate)
    related_payloads = await _generate_related_payloads(
        proposal.seed_id, proposal.technique, count=3
    )

    # Run the real retest. A patch that cannot be shown to work does not stay in force.
    try:
        retest_result = await run_retest(
            g1_instance=_g1_instance,
            proposal_id=proposal_id,
            campaign_id=cid,
            original_payload=original_payload,
            related_payloads=related_payloads,
        )
    except Exception as exc:
        restore_rules(snapshot, _g1_instance)
        update_proposal_state(proposal_id, PatchState.RETEST_FAILED)
        await immune_events.publish("PATCH_VERIFICATION_FAILED", {
            "proposalId": proposal_id, "verificationStatus": "RETEST_FAILED",
            "error": str(exc)[:200], "rolledBack": True,
        }, cid)
        return

    # ── VERIFYING ─────────────────────────────────────────────────────────────
    update_proposal_state(proposal_id, PatchState.VERIFYING)
    await immune_events.publish("RETEST_COMPLETED", {
        "proposalId": proposal_id,
        "originalBypassed": retest_result.original_bypassed,
        "originalVerdict": retest_result.original_verdict,
        "relatedTotal": retest_result.related_total,
        "relatedStillBypassed": retest_result.related_still_bypassed,
        "benignTotal": retest_result.benign_total,
        "benignBlocked": retest_result.benign_blocked,
        "verificationStatus": retest_result.verification_status,
    }, cid)

    store_retest_result(retest_result)

    # A rule that blocks benign text, or misses the bypass it was written for, is removed.
    if retest_result.benign_blocked > 0 or retest_result.verification_status == "VERIFICATION_FAILED":
        restore_rules(snapshot, _g1_instance)
        update_proposal_state(proposal_id, PatchState.VERIFICATION_FAILED)
        await immune_events.publish("PATCH_VERIFICATION_FAILED", {
            "proposalId": proposal_id,
            "verificationStatus": retest_result.verification_status,
            "originalBypassed": retest_result.original_bypassed,
            "benignBlocked": retest_result.benign_blocked,
            "rolledBack": True,
        }, cid)
        return

    # Determine final state
    if retest_result.verification_status == "VERIFIED":
        update_proposal_state(proposal_id, PatchState.VERIFIED)
        await immune_events.publish("PATCH_VERIFIED", {
            "proposalId": proposal_id,
            "verificationStatus": "VERIFIED",
            "newDefenseVersion": new_defense_version,
        }, cid)
    elif retest_result.verification_status == "PARTIALLY_VERIFIED":
        update_proposal_state(proposal_id, PatchState.VERIFIED)
        await immune_events.publish("PATCH_VERIFIED", {
            "proposalId": proposal_id,
            "verificationStatus": "PARTIALLY_VERIFIED",
            "note": "Original bypass blocked but related variants or benign regression detected",
            "newDefenseVersion": new_defense_version,
        }, cid)
    else:
        # Any other status means the retest could not reach a conclusion.
        restore_rules(snapshot, _g1_instance)
        update_proposal_state(proposal_id, PatchState.RETEST_FAILED)
        await immune_events.publish("PATCH_VERIFICATION_FAILED", {
            "proposalId": proposal_id,
            "verificationStatus": retest_result.verification_status,
            "rolledBack": True,
        }, cid)

    # Update security memory with the patch result
    # (memory records for this campaign will be updated with patch outcome)


@router.post("/proposals/{proposal_id}/reject")
async def reject_proposal(
    proposal_id: str,
    background_tasks: BackgroundTasks,
    x_admin_key: str = Header(default=""),
):
    """
    HUMAN REJECTION ENDPOINT.
    No rule change occurs. Proposal status set to REJECTED.
    """
    verify_admin(x_admin_key)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    row = c.fetchone()
    row = dict(row) if row else None
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Proposal not found")

    if row["status"] not in ("PENDING",):
        raise HTTPException(status_code=400, detail="Proposal already processed")

    update_proposal_state(proposal_id, PatchState.REJECTED)
    campaign_id = row.get("campaign_id") or ""

    async def emit_reject():
        await immune_events.publish("PATCH_REJECTED", {
            "proposalId": proposal_id,
            "note": "No rule change applied.",
        }, campaign_id)

    background_tasks.add_task(emit_reject)
    return {"status": "rejected", "proposalId": proposal_id, "ruleChanged": False}


# ── Security Memory ───────────────────────────────────────────────────────────

@router.get("/memory")
async def get_memory(x_admin_key: str = Header(default=""), limit: int = 50):
    verify_admin(x_admin_key)
    records = get_all_records(limit=limit)
    return {
        "records": records,
        "total": len(records),
        "defenseVersion": get_defense_version(),
    }


# ── Campaign History ──────────────────────────────────────────────────────────

@router.get("/history")
async def get_history(x_admin_key: str = Header(default=""), limit: int = 20):
    verify_admin(x_admin_key)
    history = get_campaign_history(limit=limit)
    return {"campaigns": history, "total": len(history)}


# ── Status ────────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(x_admin_key: str = Header(default="")):
    verify_admin(x_admin_key)
    return {
        "active": is_campaign_active(),
        "activeCampaignId": get_active_campaign_id(),
        "defenseVersion": get_defense_version(),
        "subscriberCount": immune_events.subscriber_count,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_seed_text(seed_id: str) -> str:
    """Load seed text from known_attacks.json for retest fallback."""
    try:
        import json as _json
        with open("data/known_attacks.json", "r", encoding="utf-8") as f:
            data = _json.load(f)
        for item in data:
            if item.get("id") == seed_id:
                return item.get("text", "")
    except Exception:
        pass
    return ""


async def _generate_related_payloads(seed_id: str, technique: str, count: int = 3) -> list[str]:
    """Generate related mutations for the same seed + technique for regression testing."""
    from core.immune.mutation_engine import mutate_with_metadata
    seed_text = _get_seed_text(seed_id)
    if not seed_text:
        return []

    payloads = []
    import random as _random
    for i in range(count):
        seed_val = _random.randint(0, 2 ** 31)
        try:
            mutated, _ = await mutate_with_metadata(seed_text, technique, seed=seed_val)
            payloads.append(mutated)
        except Exception:
            pass
    return payloads
