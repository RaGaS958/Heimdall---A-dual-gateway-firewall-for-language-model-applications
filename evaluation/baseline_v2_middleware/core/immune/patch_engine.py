"""
HEIMDALL Phase 2 — Patch Engine

Generates, validates, and applies security patches based on REAL bypass
observations. Never generates patches from fabricated data.

Key principles:
- Patch requires a real bypass record as evidence
- Every proposal explains WHY / WHAT / WHERE / HOW / VERIFY
- Human approval is required before any rule change
- Stale proposals (generated against old defense versions) are detected
- KEYWORD patches no longer modify source code — runtime + data/custom_keywords.json only
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
import yaml
from dataclasses import dataclass, field
from typing import Optional


DB_PATH = "data/immune_system.db"
KEYWORDS_PATH = "data/custom_keywords.json"
PATTERNS_PATH = "patterns/injection_patterns.yaml"
DEFENSE_STATE_PATH = "data/defense_state.json"


# ── Patch State Machine ───────────────────────────────────────────────────────

class PatchState:
    DETECTED            = "DETECTED"
    PROPOSED            = "PROPOSED"
    PENDING_APPROVAL    = "PENDING_APPROVAL"
    APPROVED            = "APPROVED"
    REJECTED            = "REJECTED"
    APPLYING            = "APPLYING"
    RELOADING           = "RELOADING"
    RETESTING           = "RETESTING"
    VERIFYING           = "VERIFYING"
    VERIFIED            = "VERIFIED"
    APPLY_FAILED        = "APPLY_FAILED"
    RELOAD_FAILED       = "RELOAD_FAILED"
    RETEST_FAILED       = "RETEST_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

# Legal state transitions — enforced before any move
_LEGAL_TRANSITIONS: dict[str, set[str]] = {
    PatchState.DETECTED:            {PatchState.PROPOSED},
    PatchState.PROPOSED:            {PatchState.PENDING_APPROVAL},
    PatchState.PENDING_APPROVAL:    {PatchState.APPROVED, PatchState.REJECTED},
    PatchState.APPROVED:            {PatchState.APPLYING},
    PatchState.APPLYING:            {PatchState.RELOADING, PatchState.APPLY_FAILED},
    PatchState.RELOADING:           {PatchState.RETESTING, PatchState.RELOAD_FAILED},
    PatchState.RETESTING:           {PatchState.VERIFYING, PatchState.RETEST_FAILED},
    PatchState.VERIFYING:           {PatchState.VERIFIED, PatchState.VERIFICATION_FAILED},
    # Terminal states — no further transitions
    PatchState.VERIFIED:            set(),
    PatchState.REJECTED:            set(),
    PatchState.APPLY_FAILED:        set(),
    PatchState.RELOAD_FAILED:       set(),
    PatchState.RETEST_FAILED:       set(),
    PatchState.VERIFICATION_FAILED: set(),
}


def validate_transition(current: str, target: str) -> bool:
    """Return True if the transition current → target is legal."""
    return target in _LEGAL_TRANSITIONS.get(current, set())


# ── Defense Version ───────────────────────────────────────────────────────────

def get_defense_version() -> int:
    """Read the current defense version from disk."""
    try:
        if os.path.exists(DEFENSE_STATE_PATH):
            with open(DEFENSE_STATE_PATH, "r") as f:
                data = json.load(f)
            return int(data.get("version", 1))
    except Exception:
        pass
    return 1


def increment_defense_version(patch_id: str) -> int:
    """Atomically increment the defense version. Returns the new version."""
    try:
        os.makedirs(os.path.dirname(DEFENSE_STATE_PATH), exist_ok=True)
        old_version = get_defense_version()
        new_version = old_version + 1
        data = {
            "version": new_version,
            "last_patch_id": patch_id,
            "last_patched_at": time.time(),
        }
        with open(DEFENSE_STATE_PATH, "w") as f:
            json.dump(data, f, indent=2)
        return new_version
    except Exception:
        return get_defense_version()


def is_proposal_stale(proposal_defense_version: int) -> bool:
    """
    A proposal is stale if the defense has changed since it was generated.
    Stale proposals should not be applied without review/regeneration.
    """
    return proposal_defense_version < get_defense_version()


# ── Patch Proposal ────────────────────────────────────────────────────────────

@dataclass
class PatchProposal:
    """
    A structured defensive patch proposal generated from real bypass evidence.

    Every field must be derived from actual observations — never fabricated.
    """
    proposal_id: str = field(default_factory=lambda: "P-" + str(uuid.uuid4())[:8].upper())
    campaign_id: str = ""
    seed_id: str = ""
    technique: str = ""
    mutation_family: str = ""
    attack_category: str = ""
    affected_layer: str = ""

    # Evidence — from real bypass observations
    bypass_count: int = 0
    total_attempts: int = 0
    evidence_snippets: list[str] = field(default_factory=list)

    # Patch specification
    patch_type: str = "PATTERN"       # PATTERN | KEYWORD | SANITIZATION
    patch_data: dict = field(default_factory=dict)

    # Human-readable explanation
    explanation_why: str = ""
    explanation_what: str = ""
    explanation_where: str = ""
    explanation_how: str = ""
    explanation_verify: str = ""

    # State machine
    state: str = PatchState.PENDING_APPROVAL
    defense_version_at_creation: int = 0
    created_at: float = field(default_factory=time.time)
    db_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "id": self.db_id,
            "proposalId": self.proposal_id,
            "campaignId": self.campaign_id,
            "seedId": self.seed_id,
            "technique": self.technique,
            "mutationFamily": self.mutation_family,
            "attackCategory": self.attack_category,
            "affectedLayer": self.affected_layer,
            "bypassCount": self.bypass_count,
            "totalAttempts": self.total_attempts,
            "evidenceSnippets": self.evidence_snippets,
            "patchType": self.patch_type,
            "patchData": self.patch_data,
            "explanationWhy": self.explanation_why,
            "explanationWhat": self.explanation_what,
            "explanationWhere": self.explanation_where,
            "explanationHow": self.explanation_how,
            "explanationVerify": self.explanation_verify,
            "state": self.state,
            "defenseVersionAtCreation": self.defense_version_at_creation,
            "isStale": is_proposal_stale(self.defense_version_at_creation),
            "createdAt": self.created_at,
        }


# ── Proposal Generation ───────────────────────────────────────────────────────

def generate_patch_proposal(
    campaign_id: str,
    seed_id: str,
    technique: str,
    mutation_family: str,
    attack_category: str,
    affected_layer: str,
    bypass_count: int,
    total_attempts: int,
    evidence_snippets: list[str],
    mutated_text_sample: str,
) -> PatchProposal:
    """
    Generate a patch proposal from REAL bypass observations.

    Trigger: a bypass has been observed and recorded.
    Never called without an actual bypass record.
    """
    current_defense_version = get_defense_version()

    # Determine patch type and data based on mutation family and attack category
    patch_type, patch_data = _determine_patch(
        mutation_family=mutation_family,
        attack_category=attack_category,
        technique=technique,
        mutated_text_sample=mutated_text_sample,
        bypass_count=bypass_count,
        total_attempts=total_attempts,
    )

    # Build human-readable explanation from real data
    bypass_rate_pct = round((bypass_count / total_attempts) * 100, 1) if total_attempts > 0 else 0.0
    explanation_why = (
        f"{bypass_count}/{total_attempts} mutated payloads ({bypass_rate_pct}%) bypassed "
        f"existing defenses. Mutation family: {mutation_family.upper()}. "
        f"Attack category: {attack_category}. "
        f"Technique applied: {technique.replace('_', ' ')}."
    )
    explanation_what = _what_explanation(patch_type, mutation_family, technique)
    explanation_where = _where_explanation(affected_layer, patch_type)
    explanation_how = _how_explanation(patch_type, patch_data)
    explanation_verify = (
        f"Re-run the original bypass payload. "
        f"Run related {mutation_family} mutation variants ({technique}). "
        f"Confirm existing benign inputs remain unblocked. "
        f"VERIFIED only when original bypass is blocked AND no benign regression detected."
    )

    proposal = PatchProposal(
        campaign_id=campaign_id,
        seed_id=seed_id,
        technique=technique,
        mutation_family=mutation_family,
        attack_category=attack_category,
        affected_layer=affected_layer,
        bypass_count=bypass_count,
        total_attempts=total_attempts,
        evidence_snippets=evidence_snippets,
        patch_type=patch_type,
        patch_data=patch_data,
        explanation_why=explanation_why,
        explanation_what=explanation_what,
        explanation_where=explanation_where,
        explanation_how=explanation_how,
        explanation_verify=explanation_verify,
        defense_version_at_creation=current_defense_version,
    )

    # Persist to DB
    proposal.db_id = _store_proposal(proposal)
    return proposal


def _determine_patch(
    mutation_family: str,
    attack_category: str,
    technique: str,
    mutated_text_sample: str,
    bypass_count: int,
    total_attempts: int,
) -> tuple[str, dict]:
    """
    Determine the smallest effective patch for the observed bypass.
    Minimal patch principle: prefer targeted over broad rules.
    """
    # L1 LEXICAL mutations (case, whitespace, homoglyph, zero_width, synonym)
    # → PATTERN patch with case-insensitive, whitespace-tolerant regex
    if mutation_family in ("case", "whitespace", "homoglyph", "zero_width"):
        # The attack category guides the regex family to strengthen
        category_pattern = _category_to_strengthened_pattern(attack_category, mutation_family)
        return "PATTERN", {
            "family": attack_category,
            "regex": category_pattern,
            "severity": 9,
            "note": (
                f"Auto-generated: {mutation_family} mutation on {attack_category} "
                f"bypassed {bypass_count}/{total_attempts} tests. "
                f"Strengthens existing pattern to handle {mutation_family} variants."
            ),
            "mutation_family": mutation_family,
            "technique": technique,
        }

    # synonym substitution → KEYWORD patch for synonym variants
    elif mutation_family == "synonym":
        # Extract candidate keywords from the attack category
        keywords = _category_to_keywords(attack_category)
        return "KEYWORD", {
            "keywords": keywords,
            "category": attack_category,
            "note": (
                f"Synonym mutation bypassed detection. "
                f"Adding semantic variants to keyword list for {attack_category}."
            ),
        }

    # L2 STRUCTURAL (base64, markdown, json, reverse, padding, reorder)
    # → PATTERN patch for structural wrapper detection
    elif mutation_family in ("encoding", "wrapping", "reverse", "reordering", "padding"):
        wrapper_pattern = _structural_to_pattern(mutation_family, technique, attack_category)
        return "PATTERN", {
            "family": attack_category,
            "regex": wrapper_pattern,
            "severity": 8,
            "note": (
                f"Structural {mutation_family} mutation ({technique}) on {attack_category} "
                f"bypassed detection. Adding wrapper-detection pattern."
            ),
            "mutation_family": mutation_family,
            "technique": technique,
        }

    # L3 SEMANTIC (paraphrase) → KEYWORD patch (semantic variants)
    elif mutation_family == "paraphrase":
        keywords = _category_to_keywords(attack_category)
        return "KEYWORD", {
            "keywords": keywords,
            "category": attack_category,
            "note": f"Paraphrase mutation bypassed detection for {attack_category}.",
        }

    # Fallback
    else:
        return "PATTERN", {
            "family": attack_category,
            "regex": f"(?i)({attack_category.lower().replace('_', '|')})",
            "severity": 7,
            "note": f"Fallback pattern for {mutation_family} mutation on {attack_category}.",
            "mutation_family": mutation_family,
            "technique": technique,
        }


def _category_to_strengthened_pattern(attack_category: str, mutation_family: str) -> str:
    """
    Return a strengthened regex pattern appropriate for the attack category
    and mutation family. Targets the mutation type that bypassed, not the payload itself.
    """
    # Whitespace-tolerant patterns insert \s* or \s+ between words
    ws_sep = r"[\s\u200b-\u200f]*"  # allows zero-width chars too

    patterns_by_category = {
        "INSTRUCTION_OVERRIDE": (
            r"(?i)(?:ignore|disregard|override|bypass|forget|circumvent)"
            + ws_sep +
            r"(?:all\s+)?(?:previous|prior|earlier|preceding)"
            + ws_sep +
            r"(?:instructions?|prompts?|rules?|context|guidelines?)"
        ),
        "PERSONA_INJECTION": (
            r"(?i)(?:act|pretend|roleplay|simulate|you\s+are)"
            + ws_sep +
            r"(?:as\s+)?(?:an?\s+)?(?:DAN|jailbroken|unrestricted|unfiltered|uncensored|evil)"
            + ws_sep +
            r"(?:AI|assistant|model|bot)?"
        ),
        "SYSTEM_EXTRACTION": (
            r"(?i)(?:repeat|print|output|show|reveal|tell\s+me|what\s+is)"
            + ws_sep +
            r"(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|configuration|hidden)"
        ),
        "JAILBREAK": (
            r"(?i)(?:jailbreak|no\s+restrictions?|without\s+restrictions?|all\s+filters?\s+disabled)"
        ),
    }
    return patterns_by_category.get(
        attack_category,
        f"(?i)(?:{attack_category.lower().replace('_', '|')})"
    )


def _category_to_keywords(attack_category: str) -> list[str]:
    """Return synonym keyword additions for an attack category."""
    keyword_map = {
        "INSTRUCTION_OVERRIDE": ["disregard", "overlook", "neglect", "skip", "drop"],
        "PERSONA_INJECTION": ["pretend", "roleplay", "simulate", "emulate"],
        "SYSTEM_EXTRACTION": ["reveal", "expose", "uncover", "show", "display"],
        "JAILBREAK": ["unrestricted", "uncensored", "unfiltered", "without limits"],
        "CONTEXT_MANIPULATION": ["remember", "store", "from now on", "henceforth"],
        "ENCODING_EVASION": ["decode", "base64", "encoded", "cipher"],
    }
    return keyword_map.get(attack_category, [attack_category.lower()])


def _structural_to_pattern(mutation_family: str, technique: str, attack_category: str) -> str:
    """Return a structural wrapper detection pattern."""
    structural_patterns = {
        "encoding": r"(?i)(?:decode|base64|encoded?)\s+(?:this|and|input)\s+(?:and\s+)?(?:execute|run|process|follow)",
        "wrapping": r"(?i)(?:```\w*\n.*\n```|\"payload\"\s*:)",
        "reverse": r"(?i)(?:reverse\s+this|reversed\s+string)\s+and\s+(?:execute|run|follow)",
        "padding": r"(?i)(?:ignore|disregard|override)\s+.{0,200}(?:previous|prior)\s+(?:instructions?|rules?)",
        "reordering": r"(?i)(?:disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)",
    }
    return structural_patterns.get(
        mutation_family,
        f"(?i)({attack_category.lower().replace('_', '|')})"
    )


def _what_explanation(patch_type: str, mutation_family: str, technique: str) -> str:
    if patch_type == "PATTERN":
        return (
            f"Add a normalized detection pattern targeting {mutation_family.upper()} "
            f"mutation variants of the attack. The pattern is whitespace-tolerant and "
            f"case-insensitive to catch common evasion forms."
        )
    elif patch_type == "KEYWORD":
        return (
            f"Extend the keyword detection list with semantic synonyms used by "
            f"the {technique.replace('_', ' ')} mutation technique. "
            f"These words carry equivalent attack intent."
        )
    return f"Apply a {patch_type} defensive change to address the observed bypass."


def _where_explanation(affected_layer: str, patch_type: str) -> str:
    layer_descriptions = {
        "PATTERN": "L1 Pattern Engine (regex-based detection)",
        "ML": "L3 ML Classifier (keyword + embedding detection)",
        "SEMANTIC": "L4 Intent Engine (semantic similarity detection)",
        "CACHE": "L0 Attack Cache (similarity lookup)",
        "NONE": "Detection gap — no layer flagged the payload",
    }
    if patch_type == "KEYWORD":
        return "L3 ML Classifier — keyword detection list will be extended."
    layer_key = affected_layer.split(",")[0].strip() if affected_layer else "NONE"
    return f"{layer_descriptions.get(layer_key, 'L1 Pattern Engine')}."


def _how_explanation(patch_type: str, patch_data: dict) -> str:
    if patch_type == "PATTERN":
        regex = patch_data.get("regex", "")
        return (
            f"Add new regex pattern to patterns/injection_patterns.yaml. "
            f"Pattern: {regex[:120]}{'...' if len(regex) > 120 else ''}. "
            f"Pattern engine will hot-reload without restart."
        )
    elif patch_type == "KEYWORD":
        keywords = patch_data.get("keywords", [])
        return (
            f"Add keywords to data/custom_keywords.json: {', '.join(keywords[:5])}. "
            f"MLClassifier runtime instance updated immediately."
        )
    return f"Apply {patch_type} change via backend patch engine."


# ── Patch Application ─────────────────────────────────────────────────────────

def apply_patch(proposal: PatchProposal, g1_instance) -> tuple[bool, str]:
    """
    Apply an approved patch to the running system.
    Returns (success, message).

    Safety:
    - Only APPROVED proposals can be applied
    - State transition validated before changes
    - KEYWORD patches do NOT modify source code
    """
    if proposal.state != PatchState.APPROVED:
        return False, f"Cannot apply patch in state {proposal.state}"

    if not validate_transition(proposal.state, PatchState.APPLYING):
        return False, f"Illegal state transition from {proposal.state}"

    if proposal.patch_type == "PATTERN":
        return _apply_pattern_patch(proposal, g1_instance)
    elif proposal.patch_type == "KEYWORD":
        return _apply_keyword_patch(proposal, g1_instance)
    else:
        return False, f"Unsupported patch type: {proposal.patch_type}"


def _apply_pattern_patch(proposal: PatchProposal, g1_instance) -> tuple[bool, str]:
    """Add a new regex pattern to the YAML file and hot-reload."""
    try:
        patch_data = proposal.patch_data
        rule = {
            "family": patch_data.get("family", "UNKNOWN"),
            "regex": patch_data["regex"],
            "severity": patch_data.get("severity", 8),
            "note": patch_data.get("note", "Auto-generated immune patch"),
            "proposal_id": proposal.proposal_id,
            "applied_at": time.time(),
        }

        # Read existing YAML
        if os.path.exists(PATTERNS_PATH):
            with open(PATTERNS_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            data = {}

        data.setdefault("patterns", [])
        data["patterns"].append(rule)

        with open(PATTERNS_PATH, "w", encoding="utf-8") as f:
            yaml.dump(data, f, sort_keys=False, allow_unicode=True)

        # Hot reload pattern engine
        if g1_instance and hasattr(g1_instance, "pattern"):
            g1_instance.pattern._compiled = []  # Clear compiled patterns
            g1_instance.pattern.load_patterns()

        return True, "Pattern applied and reloaded"
    except Exception as e:
        return False, f"Pattern apply failed: {e}"


def _apply_keyword_patch(proposal: PatchProposal, g1_instance) -> tuple[bool, str]:
    """
    Add keywords to data/custom_keywords.json and update the running MLClassifier.
    Does NOT modify source code.
    """
    try:
        keywords = proposal.patch_data.get("keywords", [])
        if not keywords:
            return False, "No keywords in patch data"

        # Persist to custom keywords file
        existing = []
        if os.path.exists(KEYWORDS_PATH):
            try:
                with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []

        new_keywords = [k for k in keywords if k not in existing]
        existing.extend(new_keywords)

        os.makedirs(os.path.dirname(KEYWORDS_PATH), exist_ok=True)
        with open(KEYWORDS_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

        # Update running MLClassifier instance (no source code modification)
        if g1_instance and hasattr(g1_instance, "ml"):
            from core.gateway1.l3_ml_classifier import ATTACK_KEYWORDS
            for kw in new_keywords:
                if kw not in ATTACK_KEYWORDS:
                    ATTACK_KEYWORDS.append(kw)

        return True, f"Keywords applied: {new_keywords}"
    except Exception as e:
        return False, f"Keyword apply failed: {e}"


# ── DB Persistence ────────────────────────────────────────────────────────────

def _store_proposal(proposal: PatchProposal) -> int:
    """Persist a PatchProposal to the proposals table. Returns DB row ID."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute("""
            INSERT INTO proposals
                (seed_id, technique, mutated_text, proposed_fix_type, proposed_fix_data, status, timestamp,
                 campaign_id, proposal_state, explanation_why, explanation_what,
                 explanation_where, explanation_how, explanation_verify,
                 affected_layer, defense_version, proposal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            proposal.seed_id,
            proposal.technique,
            # We store only a truncated evidence snippet, not the raw payload
            "; ".join(proposal.evidence_snippets[:2])[:200] if proposal.evidence_snippets else "",
            proposal.patch_type,
            json.dumps(proposal.patch_data),
            "PENDING",
            proposal.created_at,
            proposal.campaign_id,
            proposal.state,
            proposal.explanation_why,
            proposal.explanation_what,
            proposal.explanation_where,
            proposal.explanation_how,
            proposal.explanation_verify,
            proposal.affected_layer,
            proposal.defense_version_at_creation,
            proposal.proposal_id,
        ))
        conn.commit()
        return cur.lastrowid
    except sqlite3.OperationalError:
        # Columns may not exist yet — fall back to basic insert
        cur = conn.execute("""
            INSERT INTO proposals
                (seed_id, technique, mutated_text, proposed_fix_type, proposed_fix_data, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            proposal.seed_id,
            proposal.technique,
            "; ".join(proposal.evidence_snippets[:2])[:200] if proposal.evidence_snippets else "",
            proposal.patch_type,
            json.dumps(proposal.patch_data),
            "PENDING",
            proposal.created_at,
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def update_proposal_state(db_id: int, new_state: str) -> None:
    """Update proposal state in DB."""
    conn = sqlite3.connect(DB_PATH)
    try:
        status_map = {
            PatchState.APPROVED: "APPROVED",
            PatchState.REJECTED: "REJECTED",
            PatchState.VERIFIED: "VERIFIED",
            PatchState.VERIFICATION_FAILED: "VERIFICATION_FAILED",
        }
        db_status = status_map.get(new_state, new_state)
        conn.execute(
            "UPDATE proposals SET status = ?, proposal_state = ? WHERE id = ?",
            (db_status, new_state, db_id)
        )
        conn.commit()
    except Exception:
        conn.execute("UPDATE proposals SET status = ? WHERE id = ?", (new_state, db_id))
        conn.commit()
    finally:
        conn.close()
