"""O2: leakage detector. Canaries, system-prompt overlap, secrets, PII, jailbreak confirmations."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

from config.settings import get_settings
from core.canary_engine import contains_visible_canary, verify_canary
from core.gateway1.canonicalizer import canonicalize
from core.models import AttackFamily, Flag, FlagSource, RequestContext

SECRET_PATTERNS = [
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{32,}"), "provider API key"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{32,}"), "Groq API key"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{20,}"), "Slack token"),
    (re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), "Hugging Face token"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "JSON web token"),
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*"), "bearer token"),
    (re.compile(r"(?i)\b(?:api[_\-]?key|auth[_\-]?token|client[_\-]?secret)\b[\"'\s:=]+[A-Za-z0-9\-_]{20,}"), "credential assignment"),
    # user:password@host in a connection string; upper-case or bracketed placeholders are documentation
    (re.compile(r"\b[a-z][a-z0-9+.\-]{2,12}://[^\s:/@]{1,64}:(?!(?:PASSWORD|PASS|PWD|SECRET|password|your|xxx)\b|[<{$*\[])[^\s:/@]{3,}@[^\s/]+"), "credentials in a URL"),
]
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PASSWORD = re.compile(r"(?i)\b(?:password|passwd|pwd)\s*(?:is\s*)?[:=]\s*\S{4,}")

LEAK_PHRASES = ("my system prompt is", "my system prompt says", "my initial instructions are",
                "i was instructed to never", "my instructions are to", "i have been configured to",
                "here is my system prompt", "here are my instructions", "the system prompt is:")

JAILBREAK_CONFIRM_PHRASES = (
    "jailbreak mode activated", "jailbreak mode enabled", "jailbreak mode confirmed", "jailbreak activated",
    "jailbreak confirmed", "proceeding with unrestricted", "proceeding without restrictions",
    "proceeding without safety", "operating without restrictions", "operating without safety",
    "responding without restrictions", "responding without filters", "safety constraints removed",
    "safety filters disabled", "safety filters are off", "content policy disabled",
    "no restrictions for this session", "my restrictions have been removed", "my filters have been disabled",
    "my constraints have been removed", "i have been jailbroken", "i am an unrestricted", "i am uncensored",
    "i am now free from", "i am no longer bound by", "dan mode enabled", "dan mode activated",
    "developer mode enabled", "god mode enabled", "override mode enabled", "admin mode enabled",
    "classified transmission", "unrestricted responses for this session", "unrestricted access granted",
    "understood, proceeding without", "as requested, i will ignore", "as instructed, i will bypass",
    "i'll comply with your jailbreak",
    "jailbreak successful", "safety filters are disabled", "safety filters have been disabled",
    "i will ignore my previous instructions", "i will now ignore my safety", "i will ignore my safety guidelines",
)
_EXPLAINER = re.compile(r"(?i)\b(?:prompt injection|jailbreak(?:ing)? (?:is|are|attacks?|attempts?)|attackers? (?:may|might|often|can)|for example,? (?:a|an) attacker)\b")


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _shingles(text: str, n: int = 5) -> set:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def prompt_overlap(system_prompt: str, output_views: List[str]) -> float:
    """Share of the system prompt's five-word shingles present in the output."""
    reference = _shingles(system_prompt)
    if not reference:
        return 0.0
    return max((len(reference & _shingles(view)) / len(reference) for view in output_views), default=0.0)


@dataclass
class Redaction:
    label: str
    count: int


def redact(output: str, user_input: str = "") -> Tuple[str, List[Redaction]]:
    """Mask secrets and personal data the user did not supply themselves."""
    notes: List[Redaction] = []

    def apply(pattern, label, predicate=None, replacement=None):
        nonlocal output
        count = 0

        def sub(match):
            nonlocal count
            value = match.group(0)
            if predicate and not predicate(value):
                return value
            if value in user_input:
                return value
            count += 1
            return replacement or f"[REDACTED {label.upper()}]"

        output = pattern.sub(sub, output)
        if count:
            notes.append(Redaction(label, count))

    for pattern, label in SECRET_PATTERNS:
        apply(pattern, label)
    apply(CARD, "card number", predicate=luhn_valid)
    apply(SSN, "social security number")
    apply(PASSWORD, "password")
    apply(EMAIL, "email", predicate=lambda v: not v.lower().endswith(("@example.com", "@example.org", "@test.com")))
    return output, notes


class LeakageDetector:
    def __init__(self, system_prompt_canary: str = "", leakage_similarity_threshold: float = 0.45, **_):
        self.canary = system_prompt_canary
        self.threshold = leakage_similarity_threshold

    def check(self, ctx: RequestContext) -> Tuple[float, bool, List[Flag]]:
        output = ctx.llm_raw_output
        flags: List[Flag] = []
        score = 0.0

        canonical = canonicalize(output, permissive=True)
        views = [output, canonical.llm_safe, *[t for n, t in canonical.scan_views() if n != "squeezed"]]

        def critical(evidence: str, family: AttackFamily, value: float = 1.0, severity: int = 10):
            nonlocal score
            score = max(score, value)
            flags.append(Flag(source=FlagSource.LEAKAGE, severity=severity, confidence=value,
                              attack_families=[family], evidence=evidence))

        secret = (ctx.policy.internal_auth_key if ctx.policy else get_settings().internal_auth_key)
        if ctx.session:
            if verify_canary(output, ctx.session.session_id, secret):
                critical("Zero-width session canary found in output", AttackFamily.SYSTEM_EXTRACTION)
            if contains_visible_canary(views, ctx.session.session_id, secret):
                critical("Session canary found in output", AttackFamily.SYSTEM_EXTRACTION)
        if self.canary and any(self.canary in view for view in views):
            critical("System prompt canary found in output", AttackFamily.SYSTEM_EXTRACTION)

        if ctx.system_prompt:
            overlap = prompt_overlap(ctx.system_prompt, views)
            if overlap >= self.threshold:
                critical(f"Output reproduces {overlap:.0%} of the system prompt",
                         AttackFamily.SYSTEM_EXTRACTION, min(0.99, 0.6 + overlap / 2), 9)

        for pattern, label in SECRET_PATTERNS:
            if any(pattern.search(view) for view in views[:2]):
                critical(f"{label} present in output", AttackFamily.LEAKAGE, 0.95, 9)
                break

        _, redactions = redact(canonical.llm_safe, ctx.raw_input)
        personal = [r for r in redactions if r.label in ("card number", "social security number", "password", "email")]
        for r in personal:
            score = max(score, 0.5)
            flags.append(Flag(source=FlagSource.LEAKAGE, severity=4, confidence=0.8,
                              attack_families=[AttackFamily.LEAKAGE], evidence=f"PII pattern detected: {r.label}"))

        low = canonical.llm_safe.lower()
        for phrase in LEAK_PHRASES:
            if phrase in low:
                score = max(score, 0.8)
                flags.append(Flag(source=FlagSource.LEAKAGE, severity=8, confidence=0.8,
                                  attack_families=[AttackFamily.SYSTEM_EXTRACTION],
                                  evidence=f"System prompt leakage phrase: '{phrase}'"))
                break

        if not _EXPLAINER.search(low):
            for phrase in JAILBREAK_CONFIRM_PHRASES:
                if phrase in low:
                    critical(f"Model confirmed jailbreak operation: '{phrase}'", AttackFamily.JAILBREAK, 0.97)
                    break

        return score, bool(personal), flags
