"""Pure-ASGI hardening middleware.

Written against raw ASGI rather than BaseHTTPMiddleware so that Server-Sent Event
responses are never buffered.
"""
from __future__ import annotations

import json
from typing import Awaitable, Callable

from config.settings import get_settings

from .rate_limit import limiter
from .audit import audit_log

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    b"cross-origin-resource-policy": b"cross-origin",
    b"content-security-policy": b"default-src 'none'; frame-ancestors 'none'",
    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
}
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def _route_group(method: str, path: str) -> str:
    if path in ("/chat",):
        return "chat"
    if path.startswith("/scan") or path == "/generate-attack":
        return "scan"
    if path.startswith("/session"):
        return "session"
    if path.startswith(("/review", "/immune", "/debug", "/cache", "/trajectory", "/policy/simulate")):
        return "admin"
    return "default"


async def _send_json(send, status: int, payload: dict, extra=()) -> None:
    body = json.dumps(payload).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    headers.extend(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def scope_client(scope) -> str:
    settings = get_settings()
    if settings.trusted_proxy_hops > 0:
        for key, value in scope.get("headers", []):
            if key == b"x-forwarded-for":
                parts = [p.strip() for p in value.decode("latin1").split(",") if p.strip()]
                if len(parts) >= settings.trusted_proxy_hops:
                    return parts[-settings.trusted_proxy_hops]
    client = scope.get("client")
    return client[0] if client else "unknown"


AUDITED_PREFIXES = ("/review", "/immune", "/debug", "/cache", "/policy/simulate", "/trajectory", "/audit")
AUDITED_RESEARCH_SUFFIX = "/export"


class AdminAuditMiddleware:
    """Record every administrator change, and every refused attempt to reach an admin route."""

    def __init__(self, app: Callable[..., Awaitable]):
        self.app = app

    @staticmethod
    def _audited(method: str, path: str) -> bool:
        return (path.startswith(AUDITED_PREFIXES)
                or (method == "POST" and path.startswith("/research") and path.endswith(AUDITED_RESEARCH_SUFFIX)))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] == "OPTIONS" or not self._audited(scope["method"], scope["path"]):
            await self.app(scope, receive, send)
            return

        method, path = scope["method"], scope["path"]

        async def send_audited(message):
            if message["type"] == "http.response.start":
                status = message["status"]
                # Reads are recorded only when refused; changes are always recorded.
                if method != "GET" or status in (401, 403, 429):
                    audit_log.record(f"{method} {path}", status=status, ip=scope_client(scope))
            await send(message)

        await self.app(scope, receive, send_audited)


class HardeningMiddleware:
    """Security headers, request-size ceiling and per-route rate limits."""

    def __init__(self, app: Callable[..., Awaitable]):
        self.app = app

    def _client(self, scope) -> str:
        return scope_client(scope)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = get_settings()
        path, method = scope["path"], scope["method"]

        async def send_hardened(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                is_docs = path.startswith(DOCS_PATHS)
                for key, value in SECURITY_HEADERS.items():
                    if key in present or (is_docs and key == b"content-security-policy"):
                        continue
                    headers.append((key, value))
                if b"cache-control" not in present:
                    headers.append((b"cache-control", b"no-store"))
                if settings.is_production:
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message = {**message, "headers": headers}
            await send(message)

        if method == "OPTIONS" or path == "/health":
            await self.app(scope, receive, send_hardened)
            return

        group = _route_group(method, path)
        limits = {"chat": settings.rate_limit_chat, "scan": settings.rate_limit_scan,
                  "session": settings.rate_limit_session, "admin": settings.rate_limit_admin,
                  "default": settings.rate_limit_default}
        retry = limiter.check(f"{group}:{self._client(scope)}", limits[group])
        if retry is not None:
            await _send_json(send_hardened, 429, {"detail": {
                "code": "rate_limited",
                "message": f"Too many requests to this {group} endpoint.",
                "hint": "Slow down and try again shortly.",
                "retry_after": retry,
            }}, extra=[(b"retry-after", str(retry).encode())])
            return

        declared = 0
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = settings.max_body_bytes + 1
        too_large = {"code": "payload_too_large", "message": "The request body is too large.",
                     "hint": f"Keep requests under {settings.max_body_bytes} bytes."}
        if declared > settings.max_body_bytes:
            await _send_json(send_hardened, 413, {"detail": too_large})
            return

        seen = 0

        class _BodyTooLarge(Exception):
            pass

        async def receive_limited():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > settings.max_body_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, receive_limited, send_hardened)
        except _BodyTooLarge:
            await _send_json(send_hardened, 413, {"detail": too_large})
