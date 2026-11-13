import secrets
import time
from typing import Optional

# Maps a secure stream token to a session_id
# token -> (session_id, expires_at)
_stream_tokens: dict[str, tuple[str, float]] = {}

def create_stream_token(session_id: str, ttl: int = 3600) -> str:
    token = secrets.token_urlsafe(32)
    _stream_tokens[token] = (session_id, time.time() + ttl)
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
    expired = [t for t, (_, exp) in _stream_tokens.items() if now > exp]
    for t in expired:
        del _stream_tokens[t]
