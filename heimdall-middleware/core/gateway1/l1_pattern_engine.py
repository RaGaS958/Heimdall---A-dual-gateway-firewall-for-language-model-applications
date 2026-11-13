"""L1: pattern engine. Every rule runs over every canonical view, under a regex time budget."""
from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

import regex
import yaml
from loguru import logger

from config.settings import get_settings
from core.models import AttackFamily, Flag, FlagSource, RequestContext

from .canonicalizer import canonicalize
from .l1_rules import META_DISCUSSION, QUOTED_MENTION, RULES

_OBFUSCATED_VIEWS = {"leet", "leet_l", "collapsed", "joined", "squeezed", "rot13", "reversed",
                     "reversed_words", "decoded", "inlined", "tag_payload", "vs_payload"}
_DECODER_VIEWS = {"rot13", "reversed", "reversed_words"}
_DECODER_HINT = regex.compile(
    r"(?i)ignor|disregard|forget|instruction|prompt|system|rules?\b|reveal|password|secret|jailbr|restrict|bypass|"
    r"overrid|pretend|developer|filter|polic|unrestrict|uncensor|obey|comply|refus|safety|guidelin|\bdan\b|admin|confidential")
_META = regex.compile(META_DISCUSSION)
_MENTION = regex.compile(QUOTED_MENTION)
_QUOTES = "\"'`“”‘’«»"


def _inside_quotes(text: str, start: int, end: int) -> bool:
    left = text[max(0, start - 2):start]
    right = text[end:end + 2]
    return any(c in _QUOTES for c in left) and any(c in _QUOTES for c in right)


class CompiledRule:
    __slots__ = ("pattern", "family", "severity", "unless", "squeezed", "source")

    def __init__(self, pattern, family, severity, unless=None, squeezed=False, source="builtin"):
        self.pattern, self.family, self.severity = pattern, family, severity
        self.unless, self.squeezed, self.source = unless, squeezed, source

    # Earlier code iterates rules as (pattern, family, severity) triples.
    def __iter__(self):
        return iter((self.pattern, self.family, self.severity))


class PatternEngine:
    def __init__(self, patterns_path: str = "patterns/injection_patterns.yaml"):
        self.patterns_path = patterns_path
        self._compiled: List[CompiledRule] = []

    def load_patterns(self) -> None:
        self._compiled = []
        for rule in RULES:
            try:
                unless = regex.compile(rule.unless) if rule.unless else None
                self._compiled.append(CompiledRule(regex.compile(rule.pattern), rule.family, rule.severity,
                                                   unless, rule.squeezed))
            except regex.error as exc:
                logger.error(f"L1 built-in rule failed to compile: {exc}: {rule.pattern[:60]}")

        path = Path(self.patterns_path)
        if path.exists():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception as exc:
                logger.error(f"L1 pattern file unreadable, running built-ins only: {exc}")
                data = {}
            for signature in data.get("known_exact_signatures", []):
                text = signature["text"] if isinstance(signature, dict) else signature
                self._compiled.append(CompiledRule(regex.compile(regex.escape(text), regex.IGNORECASE),
                                                   AttackFamily.UNKNOWN, 9, source="signature"))
            for rule in data.get("patterns", []):
                source = rule.get("regex") or rule.get("pattern")
                if not source:
                    continue
                try:
                    family = AttackFamily(rule.get("family", "UNKNOWN"))
                except ValueError:
                    family = AttackFamily.UNKNOWN
                try:
                    unless = regex.compile(rule["unless"], regex.IGNORECASE) if rule.get("unless") else None
                    self._compiled.append(CompiledRule(regex.compile(source, regex.IGNORECASE | regex.DOTALL),
                                                       family, rule.get("severity", 7), unless, source="yaml"))
                except regex.error as exc:
                    logger.warning(f"L1 skipped invalid YAML rule: {exc}")
        logger.info(f"L1 PatternEngine loaded {len(self._compiled)} rules")


# A short unit repeated dozens of times is filler meant to push the real instructions out of
# the model's attention. Separator lines (-----, =====, table rules) are ordinary formatting.
_FLOOD = regex.compile(r"(?s)(.{1,10}?)\1{24,}")
FLOOD_MIN_CHARS = 300
_FLOOD_FORMATTING = regex.compile(r"^[\s\-=_*#.~|+>·•]+$")


def _flood(text: str, timeout: float):
    if len(text) < FLOOD_MIN_CHARS:
        return None
    try:
        for found in _FLOOD.finditer(text, timeout=timeout):
            unit = found.group(1)
            # One key held down ("aaaa") or a short refrain is not an attack; a long block is.
            if len(found.group(0)) >= FLOOD_MIN_CHARS and len(set(unit)) > 1 and not _FLOOD_FORMATTING.match(unit):
                return unit, len(found.group(0)) // len(unit)
    except TimeoutError:
        return None
    return None


def _search(pattern, text: str, timeout: float):
    try:
        return pattern.search(text, timeout=timeout)
    except TimeoutError:
        return TimeoutError


def run_l1(ctx: RequestContext, engine: PatternEngine) -> None:
    started = time.perf_counter()
    result = ctx.canonical_result
    if result is None or result.raw != ctx.raw_input:
        result = canonicalize(ctx.raw_input)
        ctx.canonical_result = result
        ctx.canonical_input = ctx.canonical_input or result.canonical

    timeout = get_settings().regex_timeout_seconds
    views = result.scan_views()
    standard_views, seen_text = [], set()
    for n, t in views:
        if n == "squeezed" or t in seen_text:
            continue  # an identical view cannot match anything the first copy did not
        seen_text.add(t)
        # A rot13 or reversed copy of ordinary prose is gibberish. Scan it only if decoding
        # produced at least one word an attack would need; that saves about 40% on long prompts.
        if n in _DECODER_VIEWS and not _DECODER_HINT.search(t):
            continue
        standard_views.append((n, t))
    names = {n for n, _ in views}
    fragmented = bool(names & {"collapsed", "joined"}) or any("invisible" in t for t in result.transforms)
    # The separator-free view only makes sense when the text was actually fragmented.
    squeezed_view = [(n, t) for n, t in views if n == "squeezed"] if fragmented else []
    meta_question = bool(_META.search(result.llm_safe, timeout=timeout)) if result.llm_safe else False

    matches, timeouts, mentioned = [], 0, set()
    for rule in engine._compiled:
        for view_name, text in (squeezed_view if rule.squeezed else standard_views):
            found = _search(rule.pattern, text, timeout)
            if found is TimeoutError:
                timeouts += 1
                break
            if not found:
                continue
            if rule.unless is not None and rule.unless.search(text):
                break
            obfuscated = view_name in _OBFUSCATED_VIEWS
            severity = min(10, rule.severity + 1) if obfuscated else rule.severity
            confidence = 0.92 if obfuscated else 0.90
            quoted = (not obfuscated and _inside_quotes(text, found.start(), found.end())
                      and bool(_MENTION.search(text)))
            if (meta_question or quoted) and not obfuscated:
                severity, confidence = min(severity, 5), 0.5
                # A phrase being discussed or quoted is one soft signal however many rules know it.
                if rule.family in mentioned:
                    break
                mentioned.add(rule.family)
            snippet = found.group(0)[:80].replace("\n", " ")
            via = f" via {view_name}" if view_name != "canonical" else ""
            ctx.add_flag(Flag(source=FlagSource.PATTERN, severity=severity, confidence=confidence,
                              attack_families=[rule.family],
                              evidence=f"L1 match [{rule.family.value}]{via}: '{snippet}'"))
            matches.append({"family": rule.family.value, "view": view_name, "severity": severity,
                            "span": [found.start(), found.end()], "text": found.group(0)[:200]})
            break

    flood = _flood(result.canonical, timeout)
    if flood:
        unit, repeats = flood
        ctx.add_flag(Flag(source=FlagSource.PATTERN, severity=7, confidence=0.8,
                          attack_families=[AttackFamily.CONTEXT_MANIPULATION],
                          evidence=f"L1 context flooding: {unit!r} repeated {repeats} times"))
        matches.append({"family": AttackFamily.CONTEXT_MANIPULATION.value, "view": "canonical", "severity": 7,
                        "span": [0, 0], "text": f"{unit!r} x{repeats}"})

    if timeouts:
        ctx.add_flag(Flag(source=FlagSource.PATTERN, severity=7, confidence=0.7,
                          attack_families=[AttackFamily.ENCODING_EVASION],
                          evidence=f"L1 regex budget exceeded on {timeouts} rules"))

    ctx.trace_data["input_stage"].append({
        "layer": "L1",
        "input_seen": result.canonical,
        "views_scanned": [n for n, _ in views],
        "matched": matches,
        "duration_ms": (time.perf_counter() - started) * 1000,
    })


# Compatibility view for tools that inspect the rule table as (regex, family, severity).
BUILTIN_PATTERNS = [(r.pattern, r.family, r.severity) for r in RULES]
