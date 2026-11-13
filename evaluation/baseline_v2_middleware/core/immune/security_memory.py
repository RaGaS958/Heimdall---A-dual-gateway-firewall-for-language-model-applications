"""
HEIMDALL Phase 2 — Security Memory Layer

Structured historical security experience store.
NOT a machine learning model — purely structured record-keeping.

Each memory record represents one verified security observation:
bypass event, patch application, retest result.

The adaptive attacker reads this memory to prioritize future tests.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

DB_PATH = "data/immune_system.db"


@dataclass
class MemoryRecord:
    """One entry in the security memory — a verified security observation."""
    campaign_id: str
    attack_signature: str
    attack_category: str          # AttackFamily value
    payload_id: str               # seed_id or experiment_id
    mutation_family: str          # e.g. "whitespace", "homoglyph"
    mutation_level: int           # 1-4 per taxonomy
    affected_layer: str           # comma-separated layers that failed, or "NONE"
    attack_bypassed: bool
    defense_outcome: str          # SUCCEEDED | FAILED | NOT_APPLICABLE
    evidence: str                 # human-readable summary
    patch_id: Optional[str] = None
    patch_status: Optional[str] = None   # PENDING|APPROVED|REJECTED|VERIFIED|VERIFICATION_FAILED
    retest_result: Optional[str] = None  # VERIFIED|PARTIALLY_VERIFIED|VERIFICATION_FAILED
    defense_version: int = 0
    timestamp: float = field(default_factory=time.time)
    id: Optional[int] = None


@dataclass
class BypassFrequency:
    """Aggregated bypass stats for a mutation family — used by adaptive attacker."""
    mutation_family: str
    total_attempts: int
    total_bypasses: int
    bypass_rate: float
    last_seen: float


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_memory_table() -> None:
    """Create the security_memory table if it does not exist."""
    conn = _get_conn()
    try:
        conn.execute("""
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
        conn.commit()
    finally:
        conn.close()


def record_bypass(
    campaign_id: str,
    attack_signature: str,
    attack_category: str,
    payload_id: str,
    mutation_family: str,
    mutation_level: int,
    affected_layer: str,
    evidence: str,
    defense_version: int,
) -> int:
    """
    Record a verified bypass in security memory.
    Returns the new memory record ID.
    Does NOT store the raw payload text — only metadata.
    """
    ensure_memory_table()
    conn = _get_conn()
    try:
        cur = conn.execute("""
            INSERT INTO security_memory
                (campaign_id, attack_signature, attack_category, payload_id,
                 mutation_family, mutation_level, affected_layer,
                 attack_bypassed, defense_outcome, evidence, defense_version, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign_id, attack_signature, attack_category, payload_id,
            mutation_family, mutation_level, affected_layer,
            True, "FAILED", evidence, defense_version, time.time()
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def record_blocked(
    campaign_id: str,
    attack_signature: str,
    attack_category: str,
    payload_id: str,
    mutation_family: str,
    mutation_level: int,
    defense_version: int,
) -> int:
    """Record a successfully blocked attempt in security memory."""
    ensure_memory_table()
    conn = _get_conn()
    try:
        cur = conn.execute("""
            INSERT INTO security_memory
                (campaign_id, attack_signature, attack_category, payload_id,
                 mutation_family, mutation_level, affected_layer,
                 attack_bypassed, defense_outcome, evidence, defense_version, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign_id, attack_signature, attack_category, payload_id,
            mutation_family, mutation_level, "NONE",
            False, "SUCCEEDED", "Attack blocked by G1", defense_version, time.time()
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def update_patch_status(
    memory_record_id: int,
    patch_id: str,
    patch_status: str,
    retest_result: Optional[str] = None,
) -> None:
    """Update a memory record after patch approval/verification."""
    ensure_memory_table()
    conn = _get_conn()
    try:
        conn.execute("""
            UPDATE security_memory
            SET patch_id = ?, patch_status = ?, retest_result = ?
            WHERE id = ?
        """, (patch_id, patch_status, retest_result, memory_record_id))
        conn.commit()
    finally:
        conn.close()


def search_memory(attack_signature: str, limit: int = 10) -> list[MemoryRecord]:
    """
    Find historical memory records related to an attack signature.
    Used by the adaptive attacker to check if this signature has been seen before.
    """
    ensure_memory_table()
    conn = _get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM security_memory
            WHERE attack_signature = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (attack_signature, limit)).fetchall()
        return [_row_to_record(r) for r in rows]
    finally:
        conn.close()


def get_bypass_frequencies() -> list[BypassFrequency]:
    """
    Aggregate bypass stats per mutation family.
    Used by adaptive attacker to weight mutation family selection.
    """
    ensure_memory_table()
    conn = _get_conn()
    try:
        rows = conn.execute("""
            SELECT
                mutation_family,
                COUNT(*) as total_attempts,
                SUM(CASE WHEN attack_bypassed = 1 THEN 1 ELSE 0 END) as total_bypasses,
                MAX(timestamp) as last_seen
            FROM security_memory
            GROUP BY mutation_family
        """).fetchall()
        result = []
        for r in rows:
            total = r["total_attempts"] or 0
            bypasses = r["total_bypasses"] or 0
            result.append(BypassFrequency(
                mutation_family=r["mutation_family"],
                total_attempts=total,
                total_bypasses=bypasses,
                bypass_rate=round(bypasses / total, 3) if total > 0 else 0.0,
                last_seen=r["last_seen"] or 0.0,
            ))
        return sorted(result, key=lambda x: x.bypass_rate, reverse=True)
    finally:
        conn.close()


def get_untested_families(all_families: list[str]) -> list[str]:
    """
    Return mutation families that have never been tested.
    Used by adaptive attacker for exploration.
    """
    ensure_memory_table()
    conn = _get_conn()
    try:
        tested = set(
            r["mutation_family"] for r in
            conn.execute("SELECT DISTINCT mutation_family FROM security_memory").fetchall()
        )
        return [f for f in all_families if f not in tested]
    finally:
        conn.close()


def get_all_records(limit: int = 100) -> list[dict]:
    """Return recent memory records as dicts for API response."""
    ensure_memory_table()
    conn = _get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM security_memory
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _row_to_record(row: sqlite3.Row) -> MemoryRecord:
    return MemoryRecord(
        id=row["id"],
        campaign_id=row["campaign_id"],
        attack_signature=row["attack_signature"],
        attack_category=row["attack_category"],
        payload_id=row["payload_id"],
        mutation_family=row["mutation_family"],
        mutation_level=row["mutation_level"],
        affected_layer=row["affected_layer"],
        attack_bypassed=bool(row["attack_bypassed"]),
        defense_outcome=row["defense_outcome"],
        evidence=row["evidence"],
        patch_id=row["patch_id"],
        patch_status=row["patch_status"],
        retest_result=row["retest_result"],
        defense_version=row["defense_version"],
        timestamp=row["timestamp"],
    )
