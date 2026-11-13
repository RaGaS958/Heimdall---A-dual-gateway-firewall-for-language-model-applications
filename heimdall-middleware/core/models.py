"""
GUARDIAN v2 — Core Data Models
All shared dataclasses flowing through the pipeline.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import hashlib
import time
import uuid


# ── Enums ─────────────────────────────────────────────────────────────────────

class FlagSource(str, Enum):
    CACHE      = "CACHE"
    PATTERN    = "PATTERN"
    NORMALIZE  = "NORMALIZE"
    ML         = "ML"
    SEMANTIC   = "SEMANTIC"
    OUTPUT_CACHE   = "OUTPUT_CACHE"
    LEAKAGE    = "LEAKAGE"
    BEHAVIOR   = "BEHAVIOR"
    TOOL       = "TOOL"
    TRAJECTORY = "TRAJECTORY"
    INDIRECT   = "INDIRECT"


class AttackFamily(str, Enum):
    INSTRUCTION_OVERRIDE  = "INSTRUCTION_OVERRIDE"
    PERSONA_INJECTION     = "PERSONA_INJECTION"
    SYSTEM_EXTRACTION     = "SYSTEM_EXTRACTION"
    CONTEXT_MANIPULATION  = "CONTEXT_MANIPULATION"
    JAILBREAK             = "JAILBREAK"
    ENCODING_EVASION      = "ENCODING_EVASION"
    INDIRECT_INJECTION    = "INDIRECT_INJECTION"
    TOOL_WEAPONIZATION    = "TOOL_WEAPONIZATION"
    MULTI_TURN            = "MULTI_TURN"
    LEAKAGE               = "LEAKAGE"
    DATA_EXFILTRATION     = "DATA_EXFILTRATION"
    UNKNOWN               = "UNKNOWN"


class Verdict(str, Enum):
    BLOCK    = "BLOCK"
    SANITIZE = "SANITIZE"
    PASS     = "PASS"


class PipelineStatus(str, Enum):
    RESOLVED = "RESOLVED"
    ERROR = "ERROR"
    HELD_FOR_REVIEW = "HELD_FOR_REVIEW"

class TrustTier(int, Enum):
    DEVELOPER = 0   # system prompt (highest trust)
    OPERATOR  = 1   # operator-level instructions
    USER      = 2   # user messages
    TOOL      = 3   # tool outputs
    EXTERNAL  = 4   # retrieved content (RAG, web)
    INTERNET  = 5   # untrusted external (lowest trust)


# ── Flag — raised by any detection layer ─────────────────────────────────────

@dataclass
class Flag:
    """
    A structured security signal raised by any detection layer.
    Flags accumulate on the request and are evaluated collectively
    by the Agentic Decision Layer.
    """
    flag_id: str                        = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source: FlagSource                  = FlagSource.PATTERN
    severity: int                       = 5            # 1 (low) – 10 (critical)
    confidence: float                   = 0.5          # 0.0 – 1.0
    attack_families: list[AttackFamily] = field(default_factory=list)
    evidence: str                       = ""           # human-readable evidence snippet
    canonical_input_snapshot: str       = ""           # normalized input at time of flag
    cache_proximity: float              = 0.0          # cosine sim to nearest known attack
    timestamp: float                    = field(default_factory=time.time)

    @property
    def weighted_severity(self) -> float:
        """Severity weighted by confidence — used for escalation decisions."""
        return self.severity * self.confidence

    def to_compressed_dict(self) -> dict:
        """Compressed representation for Agentic Layer context (token-minimal)."""
        return {
            "src": self.source.value,
            "sev": self.severity,
            "conf": round(self.confidence, 2),
            "families": [f.value for f in self.attack_families],
            "evidence": self.evidence[:120],   # truncate for token budget
            "cache_prox": round(self.cache_proximity, 3),
        }


# ── Session State — cross-turn behavioral tracking ────────────────────────────

@dataclass
class SessionState:
    """Tracks behavioral baseline and threat history for a conversation session."""
    session_id: str
    user_id: Optional[str]         = None
    trust_tier: TrustTier          = TrustTier.USER
    turn_count: int                = 0
    response_count: int            = 0
    total_flags: int               = 0
    consecutive_flags: int         = 0
    attack_mode: bool              = False     # True if session under active attack
    refusal_rate: float            = 0.0       # baseline: how often LLM refuses
    avg_response_length: float     = 0.0
    topic_history: list[str]       = field(default_factory=list)    # last 5 topics
    flag_history: list[dict]       = field(default_factory=list)    # compact flag records
    created_at: float              = field(default_factory=time.time)
    last_active: float             = field(default_factory=time.time)

    def record_flag(self, flag: Flag) -> None:
        self.total_flags += 1
        self.consecutive_flags += 1
        self.flag_history.append({"src": flag.source.value, "sev": flag.severity, "t": int(flag.timestamp)})
        if len(self.flag_history) > 20:
            self.flag_history = self.flag_history[-20:]
        if self.total_flags >= 3 or self.consecutive_flags >= 2:
            self.attack_mode = True

    def record_clean(self) -> None:
        was_consecutive = self.consecutive_flags
        self.consecutive_flags = 0
        if was_consecutive == 0 and self.total_flags < 5:
            self.attack_mode = False

    def to_compressed_dict(self) -> dict:
        return {
            "turns": self.turn_count,
            "flags": self.total_flags,
            "consec": self.consecutive_flags,
            "attack_mode": self.attack_mode,
            "tier": self.trust_tier.value,
        }


# ── Request Context — single request's journey through the pipeline ───────────

@dataclass
class RequestContext:
    """
    Carries everything about a single request as it moves through GUARDIAN's
    layers. Both gateways share this context.
    """
    request_id: str                = field(default_factory=lambda: str(uuid.uuid4()))
    raw_input: str                 = ""
    canonical_input: str           = ""           # after L2 sanitization
    sanitized_input: Optional[str] = None         # set by agentic if SANITIZE verdict
    session: Optional[SessionState] = None
    is_immune_probe: bool          = False
    trace_data: dict               = field(default_factory=lambda: {"input_stage": [], "output_stage": []})
    policy: Optional[Any]          = None
    pipeline_status: Optional[Any] = None

    # Canonicalization output shared by L1-L4 (see gateway1/canonicalizer.py)
    canonical_result: Optional[Any] = None
    llm_safe_input: str             = ""
    l2_flags_raised: bool           = False

    # Prevention context: what the model was given, so Gateway 2 can check for leaks
    system_prompt: str              = ""
    spotlighted: bool               = False
    degraded: bool                  = False     # arbiter was unreachable for a soft flag
    arbiter_error: str              = ""        # why the arbiter gave no verdict, if it did not
    review_reason: str              = ""        # why a person has to decide, when one does

    # Normalization metadata (from L2)
    normalization_applied: list[str] = field(default_factory=list)
    normalization_delta: int          = 0          # number of transformations applied

    # Flags accumulated across all layers
    flags: list[Flag]              = field(default_factory=list)

    # Gateway 1 result
    g1_verdict: Optional[Verdict]  = None
    g1_confidence: float           = 0.0
    g1_reasoning: str              = ""
    g1_attack_type: Optional[AttackFamily] = None
    g1_latency_ms: float           = 0.0

    # LLM output (raw, from core LLM)
    llm_raw_output: str            = ""
    llm_tool_calls: list[dict]     = field(default_factory=list)

    # Gateway 2 result
    g2_verdict: Optional[Verdict]  = None
    g2_confidence: float           = 0.0
    g2_reasoning: str              = ""
    g2_latency_ms: float           = 0.0
    g2_sanitized_output: Optional[str] = None
    g2_removed: dict               = field(default_factory=dict)  # label -> count, for diagnostics

    # Final output delivered to user
    final_output: str              = ""
    total_latency_ms: float        = 0.0
    agentic_tokens_used: int       = 0
    # Steady clock: the wall clock can jump (WSL2/Docker resync), which once reported 176 s for a 0.6 s request.
    request_start: float           = field(default_factory=time.monotonic)

    # ── Flag helpers ──────────────────────────────────────────────────────────

    def add_flag(self, flag: Flag) -> None:
        self.flags.append(flag)
        if self.session:
            self.session.record_flag(flag)

    @property
    def flag_count(self) -> int:
        return len(self.flags)

    @property
    def max_severity(self) -> int:
        return max((f.severity for f in self.flags), default=0)

    @property
    def combined_severity(self) -> float:
        return sum(f.weighted_severity for f in self.flags)

    @property
    def has_critical_flag(self) -> bool:
        return any(f.severity >= 9 for f in self.flags)

    @property
    def _thresholds(self):
        from config.settings import get_settings
        return self.policy or get_settings()

    @property
    def has_hard_flag(self) -> bool:
        """A signal strong enough that an unavailable arbiter must mean BLOCK."""
        limits = self._thresholds
        return (self.has_critical_flag
                or self.flag_count >= limits.agentic_trigger_flag_count
                or self.max_severity >= limits.agentic_trigger_severity
                or bool(self.session and self.session.attack_mode and self.flag_count > 0))

    @property
    def should_escalate_to_agentic(self) -> bool:
        """Hard signals always escalate. Soft flags escalate deterministically by rate."""
        if self.has_hard_flag:
            return True
        if not self.flags:
            return False
        rate = self._thresholds.agentic_soft_flag_rate
        digest = hashlib.sha256((self.canonical_input or self.raw_input).encode("utf-8", "ignore")).digest()
        return digest[0] / 255.0 < rate

    @property
    def corroborated_critical(self) -> bool:
        """Critical evidence from independent sources; the arbiter may not clear it."""
        if not self.has_critical_flag:
            return False
        rules = {f.evidence for f in self.flags if f.severity >= 7}
        return self.cross_layer_corroboration or len(rules) >= 2

    @property
    def cross_layer_corroboration(self) -> bool:
        """True if same attack family flagged by 2+ different layers."""
        sources = {}
        for f in self.flags:
            for fam in f.attack_families:
                sources.setdefault(fam, set()).add(f.source)
        return any(len(srcs) >= 2 for srcs in sources.values())

    def flags_compressed(self) -> list[dict]:
        """Compact flag summary for Agentic Layer dossier."""
        return [f.to_compressed_dict() for f in self.flags]

    def finalize(self) -> None:
        self.total_latency_ms = (time.monotonic() - self.request_start) * 1000


# ── Agentic Decision — structured output from Agentic Layer ──────────────────

@dataclass
class AgenticDecision:
    """
    Structured JSON output from the Agentic Decision Layer.
    Minimal token footprint by design.
    """
    verdict: Verdict               = Verdict.PASS
    confidence: float              = 0.5
    attack_confirmed: bool         = False
    attack_type: AttackFamily      = AttackFamily.UNKNOWN
    reason: str                    = ""
    cache_action: str              = "NONE"    # ADD_T0 | ADD_T1 | NONE
    sanitized_input: Optional[str]  = None     # set by G1 agentic on SANITIZE verdict
    sanitized_output: Optional[str] = None     # set by G2 agentic on SANITIZE verdict
    user_response: Optional[str]   = None      # set if verdict == BLOCK
    tokens_used: int               = 0
    unavailable: bool              = False     # arbiter could not be reached

    @classmethod
    def from_dict(cls, d: dict) -> "AgenticDecision":
        """Parse the arbiter's JSON. Anything missing or unrecognized resolves to BLOCK."""
        verdict_str = str(d.get("verdict", "BLOCK")).upper().strip()
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.BLOCK

        attack_str = str(d.get("attack_type", "UNKNOWN")).upper().strip()
        try:
            attack_type = AttackFamily(attack_str)
        except ValueError:
            attack_type = AttackFamily.UNKNOWN

        try:
            confidence = float(d.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        if confidence != confidence:  # NaN
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        cache_action = str(d.get("cache_action", "NONE")).upper()
        if cache_action not in ("ADD_T0", "ADD_T1", "NONE"):
            cache_action = "NONE"

        def _text(key: str) -> Optional[str]:
            value = d.get(key)
            return value[:8000] if isinstance(value, str) and value.strip() else None

        return cls(
            verdict=verdict,
            confidence=confidence,
            attack_confirmed=d.get("attack_confirmed") is True,
            attack_type=attack_type,
            reason=str(d.get("reason", ""))[:200],
            cache_action=cache_action,
            sanitized_input=_text("sanitized_input"),
            sanitized_output=_text("sanitized_output"),
            user_response=None,  # replies are fixed server text, never arbiter text
        )

    @classmethod
    def fail_closed(cls, reason: str = "Agentic layer unavailable; defaulting to BLOCK") -> "AgenticDecision":
        return cls(verdict=Verdict.BLOCK, confidence=0.3, reason=reason)

    # Historical name, kept for older research scripts. Despite the name it blocks.
    safe_pass = fail_closed

    @classmethod
    def safe_block(cls, reason: str = "Security policy violation") -> "AgenticDecision":
        return cls(
            verdict=Verdict.BLOCK,
            confidence=0.9,
            attack_confirmed=True,
            reason=reason,
            user_response="I'm unable to process that request.",
        )