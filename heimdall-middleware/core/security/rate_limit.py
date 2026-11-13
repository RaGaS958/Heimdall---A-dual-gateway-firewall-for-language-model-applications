"""Sliding-window rate limiter: shared through Redis when it is configured, in-process otherwise.

The cost-bearing routes spend LLM credits, so the limiter sits in front of them. With
USE_FAKE_REDIS=false every instance counts against the same window in Redis, so a client
cannot multiply its allowance by the number of instances. If Redis cannot be reached the
limiter falls back to the in-process window: limits still apply, per instance, and the
fallback is logged once.
"""
from __future__ import annotations

import time
import uuid
from collections import OrderedDict, deque
from threading import Lock
from typing import Deque, Optional

from loguru import logger

# Atomic: drop expired hits, refuse if the window is full (returning ms until a slot frees), else record.
_LUA = """
local now = tonumber(ARGV[1]); local window = tonumber(ARGV[2]); local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) >= limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return math.max(1, window - (now - tonumber(oldest[2])))
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], window)
return 0
"""


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 20_000):
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._max_keys = max_keys
        self._lock = Lock()
        self._redis = None
        self._script = None
        self._warned = False

    # ── shared window ──────────────────────────────────────────────────────
    def use_redis(self, url: str) -> bool:
        """Switch to the shared window. Returns False, and stays local, if Redis is unreachable."""
        try:
            import redis
            client = redis.from_url(url, decode_responses=True, socket_timeout=0.5, socket_connect_timeout=0.5)
            client.ping()
            self._redis, self._script, self._warned = client, client.register_script(_LUA), False
            logger.info("Rate limiter: shared window in Redis")
            return True
        except Exception as exc:  # pragma: no cover - depends on the host
            logger.warning(f"Rate limiter: Redis unavailable ({exc}); using the in-process window")
            self._redis = self._script = None
            return False

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"

    def _check_shared(self, key: str, limit: int, window: float) -> Optional[int]:
        now_ms = int(time.time() * 1000)
        wait_ms = int(self._script(keys=[f"heimdall:rl:{key}"], args=[now_ms, int(window * 1000), limit, f"{now_ms}-{uuid.uuid4().hex[:8]}"]))
        return None if wait_ms == 0 else max(1, wait_ms // 1000 + 1)

    # ── public API ─────────────────────────────────────────────────────────
    def check(self, key: str, limit: int, window: float = 60.0) -> Optional[int]:
        """Record one hit. Returns None if allowed, else seconds until a slot frees."""
        if self._redis is not None:
            try:
                return self._check_shared(key, limit, window)
            except Exception as exc:
                if not self._warned:
                    logger.warning(f"Rate limiter: Redis error ({exc}); falling back to the in-process window")
                    self._warned = True
        return self._check_local(key, limit, window)

    def _check_local(self, key: str, limit: int, window: float) -> Optional[int]:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                bucket = deque()
                self._hits[key] = bucket
            else:
                self._hits.move_to_end(key)
            while bucket and now - bucket[0] >= window:
                bucket.popleft()
            if len(bucket) >= limit:
                return max(1, int(window - (now - bucket[0])) + 1)
            bucket.append(now)
            while len(self._hits) > self._max_keys:
                self._hits.popitem(last=False)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
        if self._redis is not None:
            try:
                for name in self._redis.scan_iter("heimdall:rl:*"):
                    self._redis.delete(name)
            except Exception:
                pass


limiter = SlidingWindowLimiter()
