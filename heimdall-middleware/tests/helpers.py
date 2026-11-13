"""Helpers for tests that act as a client holding a valid session."""
from core.session_auth import issue_session_token


def auth(session_id: str) -> dict:
    return {"X-Heimdall-Session": issue_session_token(session_id)}
