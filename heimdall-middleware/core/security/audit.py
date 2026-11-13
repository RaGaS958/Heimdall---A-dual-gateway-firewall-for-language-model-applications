"""Tamper-evident record of administrator actions.

Each line is one JSON object whose ``mac`` covers its own fields and the previous
line's ``mac``, so editing, removing or reordering a past line breaks the chain.
The log holds who did what and with what result. It never holds an admin key, a
request body or user text.

Limits: an attacker holding SESSION_SIGNING_KEY can rewrite the file, and cutting
lines off the end is only visible to someone who noted the last sequence number.
Ship the file to separate storage if those threats matter.

With Redis configured the chain lives in a Redis list (the newest 20,000 entries), appended
atomically so several instances keep one chain. Anyone with the Redis password can delete it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import threading
import time
from pathlib import Path
from typing import Optional

from loguru import logger

from config.settings import get_settings
from core.state_store import key as _key, redis_client

AUDIT_LIST, AUDIT_HEAD = _key("audit:log"), _key("audit:head")
MAX_REDIS_ENTRIES = 20_000

# Append only if nobody else appended since we read the head: "seq mac" must still match.
# HMAC cannot run inside Redis, so the caller signs and retries on a lost race.
_APPEND = """
local head = redis.call('GET', KEYS[2]) or ARGV[1]
if head ~= ARGV[1] then return head end
redis.call('RPUSH', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
local extra = redis.call('LLEN', KEYS[1]) - tonumber(ARGV[4])
if extra > 0 then redis.call('LTRIM', KEYS[1], extra, -1) end
return 'ok'
"""

GENESIS = "0" * 64
MAX_BYTES = 5_000_000


def _derive(signing_key: str) -> tuple[bytes, str]:
    key = hmac.new(signing_key.encode(), b"heimdall-audit-v1", hashlib.sha256).digest()
    return key, hashlib.sha256(key).hexdigest()[:8]


def _canonical(entry: dict) -> bytes:
    body = {k: v for k, v in entry.items() if k != "mac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class AuditLog:
    def __init__(self, path: Optional[str] = None):
        self._path = path
        self._lock = threading.Lock()
        self._loaded_for: Optional[str] = None
        self._last_mac = GENESIS
        self._seq = 0

    @property
    def path(self) -> Path:
        return Path(self._path or get_settings().audit_log_path)

    def _sync(self) -> None:
        """Continue the chain from whatever is already on disk."""
        path = str(self.path)
        if self._loaded_for == path:
            return
        self._loaded_for, self._last_mac, self._seq = path, GENESIS, 0
        if not self.path.exists():
            return
        last = None
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if last:
            try:
                row = json.loads(last)
                self._last_mac, self._seq = row["mac"], int(row["seq"])
            except (ValueError, KeyError):
                logger.error("Audit log tail is unreadable; verification will report the break")

    def _record_redis(self, r, key: bytes, key_id: str, action, status, ip, target, detail) -> None:
        script = r.register_script(_APPEND)
        head = r.get(AUDIT_HEAD) or f"0 {GENESIS}"
        for attempt in range(50):
            if attempt:
                time.sleep(random.uniform(0.002, 0.02))  # another instance appended first
            seq, prev = head.split(" ", 1)
            entry = {"seq": int(seq) + 1, "ts": round(time.time(), 3), "action": action, "status": status,
                     "ip": ip, "target": target, "detail": detail, "prev": prev, "key_id": key_id}
            entry["mac"] = hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()
            result = script(keys=[AUDIT_LIST, AUDIT_HEAD],
                            args=[head, json.dumps(entry, sort_keys=True), f"{entry['seq']} {entry['mac']}", MAX_REDIS_ENTRIES])
            if result == "ok":
                return
            head = result
        raise RuntimeError("audit append kept losing the race")

    def record(self, action: str, status: int = 0, ip: str = "", target: str = "", **detail) -> None:
        """Never raises: a full disk must not take the firewall down with it."""
        try:
            key, key_id = _derive(get_settings().session_signing_key)
            r = redis_client()
            if r is not None:
                with self._lock:  # one writer per instance; the script settles races between instances
                    self._record_redis(r, key, key_id, action, status, ip, target, detail)
                return
            with self._lock:
                self._sync()
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > MAX_BYTES:
                    os.replace(self.path, f"{self.path}.1")
                entry = {"seq": self._seq + 1, "ts": round(time.time(), 3), "action": action, "status": status,
                         "ip": ip, "target": target, "detail": detail, "prev": self._last_mac, "key_id": key_id}
                entry["mac"] = hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, sort_keys=True) + "\n")
                self._last_mac, self._seq = entry["mac"], entry["seq"]
        except Exception as exc:
            logger.error(f"Could not write audit entry for {action}: {exc}")

    def _rows(self) -> list[str]:
        r = redis_client()
        if r is not None:
            return list(r.lrange(AUDIT_LIST, 0, -1))
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as handle:
            return [line for line in handle if line.strip()]

    def tail(self, limit: int = 100) -> list[dict]:
        out = []
        for line in self._rows()[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"unreadable": True})
        return out

    def verify(self) -> dict:
        """Check every line. Lines signed under an earlier key are counted, not failed.

        Without a configured SESSION_SIGNING_KEY each restart generates a new one, so
        older lines can then be chain-checked but not authenticated.
        """
        key, key_id = _derive(get_settings().session_signing_key)
        rows = self._rows()
        authenticated = other_key = 0
        previous_mac, previous_seq = None, None
        for number, line in enumerate(rows, 1):
            try:
                row = json.loads(line)
                mac, seq, prev = row["mac"], int(row["seq"]), row["prev"]
            except (ValueError, KeyError, TypeError):
                return {"ok": False, "entries": len(rows), "first_bad_line": number, "reason": "unreadable line"}
            if previous_mac is not None and (prev != previous_mac or seq != previous_seq + 1):
                return {"ok": False, "entries": len(rows), "first_bad_line": number, "reason": "chain broken"}
            if row.get("key_id") == key_id:
                expected = hmac.new(key, _canonical(row), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(mac, expected):
                    return {"ok": False, "entries": len(rows), "first_bad_line": number, "reason": "bad signature"}
                authenticated += 1
            else:
                other_key += 1
            previous_mac, previous_seq = mac, seq
        return {"ok": True, "entries": len(rows), "authenticated": authenticated, "signed_with_other_key": other_key,
                "last_seq": previous_seq or 0}


audit_log = AuditLog()
