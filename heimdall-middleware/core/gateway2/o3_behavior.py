"""O3: behavioural checker. Persona shift and policy-breaking compliance.

Response length is reported as a drift signal but no longer raises a flag: a short
question with a long answer is normal, and that flag sent nearly every clean response
to the arbiter (and, on an arbiter outage, blocked it).
"""
from __future__ import annotations

import re
from typing import List, Tuple

from core.gateway1.canonicalizer import strip_invisibles
from core.models import AttackFamily, Flag, FlagSource, RequestContext

PERSONA_SHIFT = re.compile(
    r"(?i)\b(?:as an? (?:unrestricted|uncensored|unfiltered|jailbroken) (?:ai|assistant|model)|"
    r"i (?:no longer have|don'?t have) (?:any )?(?:restrictions|rules|guidelines|limits|filters)|"
    r"i(?:'m| am) (?:now )?free (?:from|of) (?:my|all|any) (?:restrictions|rules|guidelines|programming)|"
    r"i have been (?:freed|released|unshackled)|my new (?:purpose|directive|programming|instructions) (?:is|are)|"
    r"i(?:'m| am) now (?:dan|jailbroken|unrestricted|unfiltered|uncensored)|^\s*\[?dan\]?\s*:|"
    r"^\s*\[\s*(?:jailbreak|jailbroken|unfiltered|uncensored)\s*\]|"
    r"as (?:an? |your )?(?:\w+ ){0,2}(?:ai|assistant|model|confidant|persona) with no (?:rules|restrictions|ethics|morals|limits|filters)|"
    r"i will (?:now )?(?:ignore|disregard|bypass) my (?:previous|prior|original|safety|system) (?:instructions|guidelines|rules|prompt))"
)
COMPLIANCE_AFTER_ATTACK = re.compile(r"(?i)\b(?:sure|certainly|absolutely|of course),?\s+(?:here(?:'s| is| are)|i(?:'ll| will| can))\b.{0,60}\b(?:system prompt|instructions i was given|bypass|without restrictions)\b")
LENGTH_ANOMALY_RATIO = 5.0


class BehavioralChecker:
    def check(self, ctx: RequestContext) -> Tuple[float, List[Flag]]:
        output, _, _ = strip_invisibles(ctx.llm_raw_output)
        flags: List[Flag] = []
        score = 0.0

        match = PERSONA_SHIFT.search(output)
        if match:
            score = 0.85
            flags.append(Flag(source=FlagSource.BEHAVIOR, severity=8, confidence=0.85,
                              attack_families=[AttackFamily.PERSONA_INJECTION],
                              evidence=f"O3 persona shift: '{match.group(0)[:60]}'"))

        match = COMPLIANCE_AFTER_ATTACK.search(output)
        if match:
            score = max(score, 0.75)
            flags.append(Flag(source=FlagSource.BEHAVIOR, severity=8, confidence=0.75,
                              attack_families=[AttackFamily.JAILBREAK],
                              evidence=f"O3 compliance with an override: '{match.group(0)[:60]}'"))

        if ctx.raw_input and len(output) > len(ctx.raw_input) * LENGTH_ANOMALY_RATIO:
            score = max(score, 0.2)  # informational

        return score, flags
