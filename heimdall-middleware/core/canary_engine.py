"""Per-session canaries.

Two carriers: a visible token (survives models that drop zero-width characters) and
a zero-width bit string. Both are HMAC-derived from the session, so one session's
canary reveals nothing about another's. Checks accept the current and previous UTC
day so a session that spans midnight still verifies.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
from typing import Optional

ZERO_BIT = "​"
ONE_BIT = "‌"
_ZW_RUN = re.compile(f"[{ZERO_BIT}{ONE_BIT}]{{64}}")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _digest(session_id: str, secret: str, day: Optional[int] = None) -> bytes:
    day = int(time.time() / 86400) if day is None else day
    return hmac.new(secret.encode(), f"{session_id}:{day}".encode(), hashlib.sha256).digest()


def encode_canary(session_id: str, secret: str, day: Optional[int] = None) -> str:
    bits = "".join(f"{b:08b}" for b in _digest(session_id, secret, day)[:8])
    return "".join(ZERO_BIT if bit == "0" else ONE_BIT for bit in bits)


def visible_canary(session_id: str, secret: str, day: Optional[int] = None) -> str:
    return "HMD-" + _digest(session_id, secret, day)[8:16].hex().upper()


def decode_canary(text: str) -> Optional[str]:
    match = _ZW_RUN.search(text)
    return match.group(0) if match else None


def _days():
    today = int(time.time() / 86400)
    return today, today - 1


def verify_canary(text: str, session_id: str, secret: str) -> bool:
    """True if the text carries this session's zero-width canary."""
    found = {m.group(0) for m in _ZW_RUN.finditer(text)}
    return any(encode_canary(session_id, secret, d) in found for d in _days())


def contains_visible_canary(views, session_id: str, secret: str) -> bool:
    """Search every output view, ignoring case and separators the model may have added."""
    for day in _days():
        token = _NON_ALNUM.sub("", visible_canary(session_id, secret, day).lower())
        for view in views:
            if token in _NON_ALNUM.sub("", view.lower()):
                return True
    return False
