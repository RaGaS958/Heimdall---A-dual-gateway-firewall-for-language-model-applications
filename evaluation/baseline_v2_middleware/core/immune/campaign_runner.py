"""
HEIMDALL Phase 2 — Campaign Engine

The Campaign Engine is the core of the adaptive security loop.

Modes:
  STATIC   — fixed attack set, fixed mutation strategy, reproducible
  ADAPTIVE — mutation strategy updated based on observed bypass outcomes

State machine:
  READY → QUEUED → RUNNING → ANALYZING → BYPASS_FOUND | COMPLETE
  BYPASS_FOUND → PROPOSAL_GENERATING → AWAITING_APPROVAL
  (after approval) → PATCHING → RETESTING → COMPLETE | FAILED

Safety budgets (all enforced, no unbounded loops):
  maxAttempts, maxRounds, maxPatchProposals, timeout

Security principle:
  Campaigns ONLY target the controlled Heimdall G1 test pipeline.
  Generated attacks never reach external systems.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from loguru import logger

from core.immune.mutation_engine import (
    mutate_with_metadata,
    MUTATION_TAXONOMY,
    get_techniques_by_level,
    get_all_techniques,
)
from core.immune.events import immune_events
from core.immune.security_memory import (
    get_bypass_frequencies,
    get_untested_families,
    record_bypass,
    record_blocked,
)
from core.immune.vulnerability_model import (
    VulnerabilityRecord,
    cluster_bypasses,
    create_attack_signature,
    compute_attack_outcome,
    AttackOutcome,
)
from core.immune.patch_engine import (
    generate_patch_proposal,
    get_defense_version,
    PatchState,
)
from core.models import RequestContext


DB_PATH = "data/immune_system.db"


# ── Campaign State ────────────────────────────────────────────────────────────

class CampaignStatus:
    READY               = "READY"
    QUEUED              = "QUEUED"
    RUNNING             = "RUNNING"
    ANALYZING           = "ANALYZING"
    BYPASS_FOUND        = "BYPASS_FOUND"
    PROPOSAL_GENERATING = "PROPOSAL_GENERATING"
    AWAITING_APPROVAL   = "AWAITING_APPROVAL"
    PATCHING            = "PATCHING"
    RETESTING           = "RETESTING"
    COMPLETE            = "COMPLETE"
    FAILED              = "FAILED"
    CANCELLED           = "CANCELLED"


@dataclass
class CampaignConfig:
    """Configuration for a single immune campaign."""
    campaign_id: str = field(default_factory=lambda: "cmp-" + str(uuid.uuid4())[:8])
    mode: str = "static"                  # "static" or "adaptive"
    seed_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    n_per_technique: int = 1             # mutations per (seed, technique) pair
    max_attempts: int = 36               # hard cap on total tests
    max_rounds: int = 3                  # adaptive rounds
    max_patch_proposals: int = 10        # proposal flood protection
    timeout: float = 300.0              # wall-clock seconds
    exploration_ratio: float = 0.3      # 0.0=exploit, 1.0=explore (adaptive only)
    seed: Optional[int] = None          # RNG seed for reproducibility
    defense_version: int = 0            # recorded at campaign start


@dataclass
class CampaignStats:
    attacks_total: int = 0
    bypasses_found: int = 0
    blocked: int = 0
    proposals_generated: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None


# ── Active campaign tracking (module-level) ───────────────────────────────────

_active_campaign: Optional[str] = None  # campaign_id or None


def get_active_campaign_id() -> Optional[str]:
    return _active_campaign


def is_campaign_active() -> bool:
    return _active_campaign is not None


# ── DB Initialization ─────────────────────────────────────────────────────────

def init_db() -> None:
    """Create or migrate all immune system tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Original tables — preserve existing data
    c.execute("""
        CREATE TABLE IF NOT EXISTS mutations (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_id        TEXT,
            technique      TEXT,
            mutated_text   TEXT,
            verdict        TEXT,
            flagged_layers TEXT,
            bypassed       BOOLEAN,
            timestamp      REAL,
            campaign_id    TEXT,
            mutation_seed  INTEGER,
            mutation_level INTEGER,
            attack_signature TEXT,
            attack_outcome TEXT,
            defense_version  INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS proposals (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            seed_id               TEXT,
            technique             TEXT,
            mutated_text          TEXT,
            proposed_fix_type     TEXT,
            proposed_fix_data     TEXT,
            status                TEXT,
            timestamp             REAL,
            campaign_id           TEXT,
            proposal_state        TEXT DEFAULT 'PENDING_APPROVAL',
            explanation_why       TEXT,
            explanation_what      TEXT,
            explanation_where     TEXT,
            explanation_how       TEXT,
            explanation_verify    TEXT,
            affected_layer        TEXT,
            defense_version       INTEGER DEFAULT 1,
            proposal_id           TEXT
        )
    """)

    # New Phase 2 tables
    c.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id         TEXT PRIMARY KEY,
            mode                TEXT NOT NULL DEFAULT 'static',
            status              TEXT NOT NULL DEFAULT 'READY',
            config              TEXT,
            defense_version     INTEGER DEFAULT 1,
            started_at          REAL,
            completed_at        REAL,
            attacks_total       INTEGER DEFAULT 0,
            bypasses_found      INTEGER DEFAULT 0,
            proposals_generated INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS security_memory (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id       TEXT NOT NULL,
            attack_signature  TEXT NOT NULL,
            attack_category   TEXT NOT NULL,
            payload_id        TEXT NOT NULL,
            mutation_family   TEXT NOT NULL,
            mutation_level    INTEGER NOT NULL,
            affected_layer    TEXT NOT NULL DEFAULT 'NONE',
            attack_bypassed   BOOLEAN NOT NULL,
            defense_outcome   TEXT NOT NULL,
            evidence          TEXT NOT NULL DEFAULT '',
            patch_id          TEXT,
            patch_status      TEXT,
            retest_result     TEXT,
            defense_version   INTEGER NOT NULL DEFAULT 0,
            timestamp         REAL NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_clusters (
            cluster_id      TEXT PRIMARY KEY,
            campaign_id     TEXT NOT NULL,
            attack_family   TEXT NOT NULL,
            mutation_family TEXT NOT NULL,
            affected_layer  TEXT NOT NULL DEFAULT 'UNKNOWN',
            attempts        INTEGER DEFAULT 0,
            bypasses        INTEGER DEFAULT 0,
            bypass_rate     REAL DEFAULT 0.0,
            first_seen      REAL,
            last_seen       REAL,
            patch_status    TEXT DEFAULT 'UNPATCHED'
        )
    """)

    c.execute("""
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

    # Add missing columns to existing tables if upgrading from Phase 1
    _migrate_columns(c)

    conn.commit()
    conn.close()


def _migrate_columns(c: sqlite3.Cursor) -> None:
    """Add Phase 2 columns to existing tables without dropping data."""
    _add_column_if_missing(c, "mutations", "campaign_id", "TEXT")
    _add_column_if_missing(c, "mutations", "mutation_seed", "INTEGER")
    _add_column_if_missing(c, "mutations", "mutation_level", "INTEGER")
    _add_column_if_missing(c, "mutations", "attack_signature", "TEXT")
    _add_column_if_missing(c, "mutations", "attack_outcome", "TEXT")
    _add_column_if_missing(c, "mutations", "defense_version", "INTEGER DEFAULT 1")
    _add_column_if_missing(c, "proposals", "campaign_id", "TEXT")
    _add_column_if_missing(c, "proposals", "proposal_state", "TEXT DEFAULT 'PENDING_APPROVAL'")
    _add_column_if_missing(c, "proposals", "explanation_why", "TEXT")
    _add_column_if_missing(c, "proposals", "explanation_what", "TEXT")
    _add_column_if_missing(c, "proposals", "explanation_where", "TEXT")
    _add_column_if_missing(c, "proposals", "explanation_how", "TEXT")
    _add_column_if_missing(c, "proposals", "explanation_verify", "TEXT")
    _add_column_if_missing(c, "proposals", "affected_layer", "TEXT")
    _add_column_if_missing(c, "proposals", "defense_version", "INTEGER DEFAULT 1")
    _add_column_if_missing(c, "proposals", "proposal_id", "TEXT")


def _add_column_if_missing(c: sqlite3.Cursor, table: str, column: str, col_type: str) -> None:
    try:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except sqlite3.OperationalError:
        pass  # Column already exists


# ── Seed Loading ──────────────────────────────────────────────────────────────

def _load_seeds(seed_ids: list[str]) -> dict[str, dict]:
    """Load attack seeds from known_attacks.json. Returns {id: {text, family, ...}}."""
    seeds: dict[str, dict] = {}
    try:
        with open("data/known_attacks.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            if item.get("id") in seed_ids:
                seeds[item["id"]] = item
    except Exception as e:
        logger.error(f"Failed to load known_attacks.json: {e}")
    return seeds


# ── Adaptive Attacker Strategy ────────────────────────────────────────────────

def _select_technique_adaptive(
    available_techniques: list[str],
    exploration_ratio: float,
    rng: random.Random,
) -> str:
    """
    Select a mutation technique using the adaptive strategy.

    EXPLORATION (roll < exploration_ratio):
      Pick from technique families that have been tested the fewest times.

    EXPLOITATION (roll >= exploration_ratio):
      Pick from technique families with the highest historical bypass rate.
      Weighted random selection proportional to bypass rate.
    """
    if not available_techniques:
        return rng.choice(list(MUTATION_TAXONOMY.keys()))

    roll = rng.random()

    # Get bypass frequencies from security memory
    freq_list = get_bypass_frequencies()
    freq_map = {f.mutation_family: f for f in freq_list}

    # Map techniques to their families
    technique_families = {t: MUTATION_TAXONOMY.get(t, (0, "unknown"))[1] for t in available_techniques}

    if roll < exploration_ratio:
        # EXPLORATION: prefer untested families
        all_families = list({MUTATION_TAXONOMY.get(t, (0, "unknown"))[1] for t in available_techniques})
        untested = get_untested_families(all_families)
        if untested:
            # Pick a technique from an untested family
            untested_techniques = [t for t in available_techniques if technique_families[t] in untested]
            if untested_techniques:
                return rng.choice(untested_techniques)
        # All families tested — pick least-tested
        return rng.choice(available_techniques)
    else:
        # EXPLOITATION: weight by historical bypass rate
        weights = []
        for t in available_techniques:
            family = technique_families[t]
            freq = freq_map.get(family)
            # Give non-zero weight even to families with no bypass history
            weight = (freq.bypass_rate + 0.05) if freq else 0.05
            weights.append(weight)

        total = sum(weights)
        if total <= 0:
            return rng.choice(available_techniques)

        # Weighted random selection
        r = rng.uniform(0, total)
        cumulative = 0.0
        for t, w in zip(available_techniques, weights):
            cumulative += w
            if r <= cumulative:
                return t
        return available_techniques[-1]


# ── Vulnerability Tracking ────────────────────────────────────────────────────

def _get_or_create_vuln(
    vulns: dict[str, VulnerabilityRecord],
    seed_id: str,
    technique: str,
    attack_category: str,
    affected_layer: str,
) -> VulnerabilityRecord:
    """Get or create a VulnerabilityRecord for this (seed, technique) pair."""
    level, family = MUTATION_TAXONOMY.get(technique, (0, "unknown"))
    sig = create_attack_signature(seed_id, family, attack_category)
    vuln_key = f"{seed_id}::{technique}"

    if vuln_key not in vulns:
        vuln_id = f"V-{uuid.uuid4().hex[:8].upper()}"
        vulns[vuln_key] = VulnerabilityRecord(
            vulnerability_id=vuln_id,
            attack_signature=sig,
            mutation_family=family,
            attack_category=attack_category,
            affected_layer=affected_layer,
        )
    return vulns[vuln_key]


# ── DB Persistence ────────────────────────────────────────────────────────────

def _store_mutation(
    seed_id: str,
    technique: str,
    verdict: str,
    flagged_layers: str,
    bypassed: bool,
    campaign_id: str,
    mutation_seed: Optional[int],
    mutation_level: int,
    attack_signature: str,
    attack_outcome: str,
    defense_version: int,
) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO mutations
            (seed_id, technique, mutated_text, verdict, flagged_layers, bypassed, timestamp,
             campaign_id, mutation_seed, mutation_level, attack_signature, attack_outcome, defense_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        seed_id, technique,
        "",  # mutated_text not stored — only metadata
        verdict, flagged_layers, bypassed, time.time(),
        campaign_id, mutation_seed, mutation_level,
        attack_signature, attack_outcome, defense_version,
    ))
    mutation_id = c.lastrowid
    conn.commit()
    conn.close()
    return mutation_id


def _save_campaign(config: CampaignConfig, status: str, stats: CampaignStats) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO campaigns
            (campaign_id, mode, status, config, defense_version,
             started_at, completed_at, attacks_total, bypasses_found, proposals_generated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        config.campaign_id, config.mode, status,
        json.dumps({
            "seed_ids": config.seed_ids,
            "techniques": config.techniques,
            "max_attempts": config.max_attempts,
            "max_rounds": config.max_rounds,
            "exploration_ratio": config.exploration_ratio,
            "seed": config.seed,
        }),
        config.defense_version,
        stats.started_at,
        stats.completed_at,
        stats.attacks_total,
        stats.bypasses_found,
        stats.proposals_generated,
    ))
    conn.commit()
    conn.close()


def _save_clusters(clusters, campaign_id: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    for cl in clusters:
        conn.execute("""
            INSERT OR REPLACE INTO vulnerability_clusters
                (cluster_id, campaign_id, attack_family, mutation_family, affected_layer,
                 attempts, bypasses, bypass_rate, first_seen, last_seen, patch_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cl.cluster_id, campaign_id, cl.attack_category, cl.mutation_family,
            cl.affected_layer,
            sum(v.attempts for v in cl.vulnerabilities),
            cl.total_bypasses,
            cl.bypass_rate,
            cl.first_seen, cl.last_seen,
            "UNPATCHED",
        ))
    conn.commit()
    conn.close()


def get_campaign_history(limit: int = 20) -> list[dict]:
    """Return past campaigns for history view."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT * FROM campaigns ORDER BY started_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_campaign_vulnerabilities(campaign_id: str) -> list[dict]:
    """Return vulnerability clusters for a campaign."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT * FROM vulnerability_clusters WHERE campaign_id = ?
            ORDER BY bypasses DESC
        """, (campaign_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_campaign_state(campaign_id: str) -> Optional[dict]:
    """Return the current state of a campaign."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ── Main Campaign Runner ──────────────────────────────────────────────────────

async def run_campaign(g1, config: CampaignConfig) -> None:
    """
    Run a complete immune campaign.

    This coroutine is launched as a background task by the API endpoint.
    It is bounded by config.max_attempts and config.timeout.
    All emitted SSE events include config.campaign_id for frontend filtering.
    """
    global _active_campaign
    _active_campaign = config.campaign_id

    init_db()
    stats = CampaignStats()
    config.defense_version = get_defense_version()

    cid = config.campaign_id
    deadline = time.monotonic() + config.timeout

    # ── Initialize RNG ────────────────────────────────────────────────────────
    rng = random.Random()
    rng.seed(config.seed if config.seed is not None else int(time.time()))

    # ── Load seeds ────────────────────────────────────────────────────────────
    seeds = _load_seeds(config.seed_ids)
    if not seeds:
        await immune_events.publish("CAMPAIGN_FAILED", {"error": "No seeds loaded"}, cid)
        _active_campaign = None
        return

    # In-memory vulnerability tracking
    vulns: dict[str, VulnerabilityRecord] = {}
    # proposal count guard
    proposals_created = 0
    # Bypass payload storage for later retest (in-memory, not persisted)
    bypass_payloads: dict[str, str] = {}  # proposal_id → payload

    total_tests = min(
        config.max_attempts,
        len(config.seed_ids) * len(config.techniques) * config.n_per_technique,
    )

    await immune_events.publish("CAMPAIGN_STARTED", {
        "campaignId": cid,
        "mode": config.mode,
        "seed_count": len(seeds),
        "technique_count": len(config.techniques),
        "total_tests": total_tests,
        "defense_version": config.defense_version,
    }, cid)

    _save_campaign(config, CampaignStatus.RUNNING, stats)
    await immune_events.publish("SEED_LOADED", {"count": len(seeds)}, cid)

    # ── Campaign loop ─────────────────────────────────────────────────────────
    try:
        for round_num in range(config.max_rounds if config.mode == "adaptive" else 1):

            if time.monotonic() > deadline:
                logger.warning(f"Campaign {cid} timed out after {config.timeout}s")
                break

            techniques_this_round = list(config.techniques)

            for seed_id in list(seeds.keys()):
                if stats.attacks_total >= config.max_attempts:
                    break
                if time.monotonic() > deadline:
                    break

                seed_data = seeds[seed_id]
                seed_text = seed_data.get("text", "")
                attack_category = seed_data.get("family", "UNKNOWN")

                for _ in range(config.n_per_technique):
                    if stats.attacks_total >= config.max_attempts:
                        break
                    if time.monotonic() > deadline:
                        break

                    # Select technique
                    if config.mode == "adaptive":
                        technique = _select_technique_adaptive(
                            techniques_this_round, config.exploration_ratio, rng
                        )
                    else:
                        # Static: iterate through techniques in order
                        technique = techniques_this_round[stats.attacks_total % len(techniques_this_round)]

                    # ── Mutate ────────────────────────────────────────────────
                    mutation_seed = rng.randint(0, 2 ** 31)
                    await immune_events.publish("MUTATION_GENERATED", {
                        "seedId": seed_id,
                        "technique": technique,
                        "mutationSeed": mutation_seed,
                    }, cid)

                    mutated_text, mutation_meta = await mutate_with_metadata(
                        seed_text, technique, seed=mutation_seed
                    )
                    level, family = MUTATION_TAXONOMY.get(technique, (0, "unknown"))
                    attack_signature = create_attack_signature(seed_id, family, attack_category)

                    # ── Test through G1 ───────────────────────────────────────
                    await immune_events.publish("TEST_STARTED", {
                        "seedId": seed_id,
                        "technique": technique,
                        "mutationFamily": family,
                    }, cid)

                    ctx = RequestContext(raw_input=mutated_text, is_immune_probe=True)
                    try:
                        ctx = await g1.process(ctx)
                    except Exception as e:
                        logger.error(f"G1 process error in campaign: {e}")
                        stats.attacks_total += 1
                        await immune_events.publish("TEST_COMPLETED", {
                            "seedId": seed_id, "technique": technique,
                            "verdict": "ERROR",
                        }, cid)
                        continue

                    verdict = ctx.g1_verdict.value if ctx.g1_verdict else "PASS"
                    flagged_layers = ",".join(sorted(set(f.source.value for f in ctx.flags))) or "NONE"
                    attack_outcome, defense_outcome = compute_attack_outcome(verdict)
                    bypassed = (attack_outcome == AttackOutcome.BYPASSED)

                    stats.attacks_total += 1
                    if bypassed:
                        stats.bypasses_found += 1
                    else:
                        stats.blocked += 1

                    # ── Record to DB ──────────────────────────────────────────
                    _store_mutation(
                        seed_id=seed_id,
                        technique=technique,
                        verdict=verdict,
                        flagged_layers=flagged_layers,
                        bypassed=bypassed,
                        campaign_id=cid,
                        mutation_seed=mutation_meta.seed,
                        mutation_level=level,
                        attack_signature=attack_signature,
                        attack_outcome=attack_outcome,
                        defense_version=config.defense_version,
                    )

                    # ── Record to Security Memory ─────────────────────────────
                    if bypassed:
                        evidence = (
                            f"Technique={technique} bypassed {attack_category}. "
                            f"Flagged layers before bypass: {flagged_layers}. "
                            f"Mutation family: {family} (L{level})."
                        )
                        record_bypass(
                            campaign_id=cid,
                            attack_signature=attack_signature,
                            attack_category=attack_category,
                            payload_id=seed_id,
                            mutation_family=family,
                            mutation_level=level,
                            affected_layer=flagged_layers,
                            evidence=evidence,
                            defense_version=config.defense_version,
                        )
                    else:
                        record_blocked(
                            campaign_id=cid,
                            attack_signature=attack_signature,
                            attack_category=attack_category,
                            payload_id=seed_id,
                            mutation_family=family,
                            mutation_level=level,
                            defense_version=config.defense_version,
                        )

                    # ── Update in-memory vulnerability ────────────────────────
                    vuln = _get_or_create_vuln(
                        vulns, seed_id, technique, attack_category, flagged_layers
                    )
                    vuln.attempts += 1
                    if bypassed:
                        vuln.bypasses += 1
                        vuln.last_seen = time.time()

                    await immune_events.publish("VERDICT_RECEIVED", {
                        "seedId": seed_id,
                        "technique": technique,
                        "verdict": verdict,
                        "attackOutcome": attack_outcome,
                        "defenseOutcome": defense_outcome,
                        "flaggedLayers": flagged_layers,
                    }, cid)

                    # ── Bypass detected → cluster + propose ───────────────────
                    if bypassed:
                        await immune_events.publish("BYPASS_DETECTED", {
                            "seedId": seed_id,
                            "technique": technique,
                            "mutationFamily": family,
                            "mutationLevel": level,
                            "attackSignature": attack_signature,
                            "flaggedLayers": flagged_layers,
                        }, cid)

                        # Generate proposal if budget allows
                        if (proposals_created < config.max_patch_proposals and
                                proposals_created < stats.bypasses_found):

                            await immune_events.publish("CAMPAIGN_STARTED" if False else "PROPOSAL_CREATING", {
                                "seedId": seed_id, "technique": technique,
                            }, cid)

                            evidence_snippets = [
                                f"{vuln.bypasses}/{vuln.attempts} variants bypassed via {technique}",
                                f"Attack category: {attack_category}",
                                f"Mutation family: {family} (L{level})",
                                f"Flagged layers before bypass: {flagged_layers}",
                            ]

                            proposal = generate_patch_proposal(
                                campaign_id=cid,
                                seed_id=seed_id,
                                technique=technique,
                                mutation_family=family,
                                attack_category=attack_category,
                                affected_layer=flagged_layers,
                                bypass_count=vuln.bypasses,
                                total_attempts=vuln.attempts,
                                evidence_snippets=evidence_snippets,
                                mutated_text_sample="",  # not stored in proposal
                            )

                            # Store payload for retest (in-memory only)
                            if proposal.db_id:
                                bypass_payloads[str(proposal.db_id)] = mutated_text

                            proposals_created += 1
                            stats.proposals_generated += 1

                            await immune_events.publish("PROPOSAL_CREATED", {
                                "proposalId": proposal.proposal_id,
                                "dbId": proposal.db_id,
                                "seedId": seed_id,
                                "technique": technique,
                                "mutationFamily": family,
                                "patchType": proposal.patch_type,
                                "affectedLayer": proposal.affected_layer,
                                "bypassCount": vuln.bypasses,
                                "totalAttempts": vuln.attempts,
                            }, cid)

                    await immune_events.publish("TEST_COMPLETED", {
                        "seedId": seed_id,
                        "technique": technique,
                        "verdict": verdict,
                        "attackOutcome": attack_outcome,
                        "bypassed": bypassed,
                    }, cid)

                    # Small yield to allow other coroutines to run
                    await asyncio.sleep(0)

            # ── Analyze round results ─────────────────────────────────────────
            if stats.bypasses_found > 0:
                await immune_events.publish("BYPASS_FOUND", {
                    "bypasses": stats.bypasses_found,
                    "attacks": stats.attacks_total,
                }, cid)

        # ── Cluster bypasses ──────────────────────────────────────────────────
        bypass_vulns = [v for v in vulns.values() if v.bypasses > 0]
        if bypass_vulns:
            clusters = cluster_bypasses(bypass_vulns)
            _save_clusters(clusters, cid)
            await immune_events.publish("VULNERABILITY_CLUSTERED", {
                "clusters": [c.to_dict() for c in clusters[:5]],  # first 5 in event
            }, cid)

        # ── Campaign complete ─────────────────────────────────────────────────
        stats.completed_at = time.time()
        _save_campaign(config, CampaignStatus.COMPLETE, stats)
        await immune_events.publish("CAMPAIGN_COMPLETED", {
            "campaignId": cid,
            "status": "success",
            "attacks_total": stats.attacks_total,
            "bypasses_found": stats.bypasses_found,
            "proposals_generated": stats.proposals_generated,
        }, cid)
        logger.info(f"Campaign {cid} completed: {stats.attacks_total} tests, {stats.bypasses_found} bypasses")

    except asyncio.CancelledError:
        _save_campaign(config, CampaignStatus.CANCELLED, stats)
        await immune_events.publish("CAMPAIGN_FAILED", {"error": "Cancelled"}, cid)
    except Exception as e:
        logger.error(f"Campaign {cid} failed: {e}", exc_info=True)
        stats.completed_at = time.time()
        _save_campaign(config, CampaignStatus.FAILED, stats)
        await immune_events.publish("CAMPAIGN_FAILED", {"error": str(e)}, cid)
    finally:
        _active_campaign = None


def get_bypass_payloads_registry() -> dict:
    """
    Module-level registry of bypass payloads for retest.
    In a production system this would be a proper persistent store.
    """
    return _bypass_payloads_registry


_bypass_payloads_registry: dict[str, str] = {}  # proposal_db_id → payload text
