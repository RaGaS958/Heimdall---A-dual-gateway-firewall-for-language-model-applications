"""Server-issued sessions and short-lived stream tokens.

A client can no longer name its own session. POST /session/init returns a
session_id and an HMAC session_token, and later requests prove ownership with
that token. This closes three holes: session fixation, reading another session's
SSE stream by guessing its ID, and dodging a session lock by renaming the session.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from typing import Optional

from config.settings import get_settings

_MAX_STREAM_TOKENS = 20_000
_stream_tokens: "OrderedDict[str, tuple[str, float]]" = OrderedDict()


def _sign(session_id: str) -> str:
    key = get_settings().session_signing_key.encode()
    return hmac.new(key, session_id.encode(), hashlib.sha256).hexdigest()


def new_session_id() -> str:
    return "sid_" + secrets.token_hex(16)


def issue_session_token(session_id: str) -> str:
    return f"{session_id}.{_sign(session_id)}"


def verify_session_token(token: Optional[str]) -> Optional[str]:
    """Return the session_id a token proves, or None."""
    if not token or "." not in token or len(token) > 256:
        return None
    session_id, signature = token.rsplit(".", 1)
    if hmac.compare_digest(signature, _sign(session_id)):
        return session_id
    return None


def create_stream_token(session_id: str, ttl: Optional[int] = None) -> str:
    token = secrets.token_urlsafe(32)
    lifetime = ttl if ttl is not None else get_settings().stream_token_ttl
    _stream_tokens[token] = (session_id, time.time() + lifetime)
    while len(_stream_tokens) > _MAX_STREAM_TOKENS:
        _stream_tokens.popitem(last=False)
    return token


def get_session_for_token(token: str) -> Optional[str]:
    entry = _stream_tokens.get(token)
    if not entry:
        return None
    session_id, expires_at = entry
    if time.time() > expires_at:
        del _stream_tokens[token]
        return None
    return session_id


def cleanup_expired_tokens() -> None:
    now = time.time()
    for token in [t for t, (_, exp) in _stream_tokens.items() if now > exp]:
        del _stream_tokens[token]
