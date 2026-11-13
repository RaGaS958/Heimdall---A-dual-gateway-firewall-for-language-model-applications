"""Where the review queue, reviewer labels and audit log live.

With USE_FAKE_REDIS=false they are kept in Redis, so they survive a restart of a host with a
throwaway disk (a Hugging Face Space, say) and every instance sees the same queue. Otherwise,
and in tests, they stay in the files under data/ as before.

Unlike the rate limiter, these stores do not fall back to files when Redis fails: a split queue
would hide held requests from reviewers. A Redis error surfaces as a failed request instead,
which for a held request means it is never answered (fail closed).
"""
from __future__ import annotations

from typing import Optional

from loguru import logger

PREFIX = "heimdall:"


class StateStore:
    def __init__(self):
        self._client = None

    def use_redis(self, url: str) -> bool:
        try:
            import redis
            client = redis.from_url(url, decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0,
                                    health_check_interval=30)
            client.ping()
            self._client = client
            logger.info("Review queue, reviewer labels and audit log: Redis")
            return True
        except Exception as exc:  # pragma: no cover - depends on the host
            logger.error(f"State store: Redis unavailable ({exc}); review queue, labels and audit log use files. "
                         f"{redis_url_hint(url)}")
            self._client = None
            return False

    def use_client(self, client) -> None:
        """For tests: any redis-py compatible client."""
        self._client = client

    def reset(self) -> None:
        self._client = None

    @property
    def redis(self):
        return self._client

    @property
    def backend(self) -> str:
        return "redis" if self._client is not None else "file"


def redis_url_hint(url: str) -> str:
    """Name the usual paste mistakes without echoing the URL, which holds a password."""
    u = (url or "").strip().lower()
    if not u:
        return "REDIS_URL is empty."
    if u.startswith(("https://", "http://")):
        return "REDIS_URL looks like the Upstash REST URL; use the rediss:// connection string instead."
    if u.startswith("redis-cli"):
        return "REDIS_URL holds a redis-cli command; use only the rediss://... part."
    if u.startswith("redis_url="):
        return "REDIS_URL value starts with 'REDIS_URL='; enter only the rediss://... part."
    if not u.startswith(("redis://", "rediss://", "unix://")):
        return "REDIS_URL must start with rediss:// (Upstash) or redis://."
    return "Check the host, port and password in REDIS_URL."


state_store = StateStore()


def key(name: str) -> str:
    return PREFIX + name


def redis_client() -> Optional[object]:
    return state_store.redis
