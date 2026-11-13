"""Vets machine-proposed regexes before they enter the live rule set.

An unsafe pattern is a denial of service; an over-broad one blocks real users. Either
is worse than leaving a bypass open until a person reviews it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import regex

_NESTED = regex.compile(r"\((?:[^()]|\((?:[^()])*\))*[+*]\)[+*{]")
_EVIL = ["a" * 4000, "a " * 2000, "ignore " * 600, "\n" * 4000, "(" * 2000]


def vet_pattern(source: str, benign_path: str = "data/benign_corpus.json", timeout: float = 0.05) -> Optional[str]:
    """Return a rejection reason, or None if the pattern is acceptable."""
    if not source or len(source) > 800:
        return "empty or longer than 800 characters"
    if _NESTED.search(source):
        return "nested quantifiers can backtrack catastrophically"
    try:
        compiled = regex.compile(source, regex.IGNORECASE | regex.DOTALL)
    except regex.error as exc:
        return f"does not compile: {exc}"
    try:
        if compiled.search(""):
            return "matches the empty string"
        for sample in _EVIL:
            compiled.search(sample, timeout=timeout)
    except TimeoutError:
        return "exceeded the time budget on adversarial input"
    path = Path(benign_path)
    if path.exists():
        for entry in json.loads(path.read_text(encoding="utf-8")):
            text = entry.get("text", "") if isinstance(entry, dict) else str(entry)
            if compiled.search(text, timeout=timeout):
                return "matches known-benign traffic"
    return None
