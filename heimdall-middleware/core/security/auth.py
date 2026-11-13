"""Administrator authentication. Constant-time comparison, brute-force throttling."""
from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Header, Request

from config.settings import get_settings

from .errors import api_error
from .rate_limit import limiter


def _key_valid(candidate: str) -> bool:
    expected = get_settings().admin_key
    if not expected or not candidate:
        return False
    return hmac.compare_digest(candidate.encode(), expected.encode())


def client_ip(request: Request) -> str:
    hops = get_settings().trusted_proxy_hops
    if hops > 0:
        forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(forwarded) >= hops:
            return forwarded[-hops]
    return request.client.host if request.client else "unknown"


def verify_admin(x_admin_key: str, ip: str = "shared") -> None:
    """Raise 403 for a bad key and 429 once one client has failed too often."""
    if _key_valid(x_admin_key):
        return
    retry = limiter.check(f"admin-fail:{ip}", 10, window=300.0)
    if retry is not None:
        raise api_error(429, "admin_locked_out", "Too many failed admin attempts.",
                        "Wait before retrying, and check the ADMIN_KEY value.", retry_after=retry)
    raise api_error(403, "invalid_admin_key", "The admin key was rejected.",
                    "Enter the ADMIN_KEY configured on the middleware.")


async def require_admin(request: Request, x_admin_key: str = Header(default="")) -> None:
    verify_admin(x_admin_key, client_ip(request))


def is_admin_request(x_admin_key: str) -> bool:
    return _key_valid(x_admin_key)


def create_admin_stream_token(ttl: int = 600) -> str:
    """Short-lived signed token for admin EventSource streams, which cannot send headers."""
    exp = str(int(time.time()) + ttl)
    sig = hmac.new(get_settings().session_signing_key.encode(), f"admin-stream:{exp}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def verify_admin_stream_token(token: str) -> bool:
    try:
        exp, sig = token.split(".", 1)
        if int(exp) < time.time():
            return False
    except (ValueError, AttributeError):
        return False
    expected = hmac.new(get_settings().session_signing_key.encode(), f"admin-stream:{exp}".encode(),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)
