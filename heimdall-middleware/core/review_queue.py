import json
import time
import os
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from core.models import RequestContext
import threading

from loguru import logger

from core.state_store import key as _key, redis_client

MAX_ITEMS = 2000
ITEMS, PENDING, ORDER = _key("review:items"), _key("review:pending"), _key("review:order")

QUEUE_FILE = "data/review_queue.json"  # default; the live queue uses settings.review_queue_path

@dataclass
class ReviewQueueItem:
    id: str
    request_id: str
    session_id: str
    original_input: str
    agentic_reason: str
    agentic_confidence: float
    flags_summary: List[Dict]
    timestamp: float
    status: str = "pending"  # pending, approved, rejected, timeout
    reviewer_note: str = ""
    decided_at: Optional[float] = None
    system_msg: Optional[str] = None
    review_reason: str = ""

class ReviewQueue:
    def __init__(self, file_path=None):
        if file_path is None:
            from config.settings import get_settings
            file_path = get_settings().review_queue_path
        self.file_path = file_path
        self.lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        # An unwritable folder must not stop the service from starting; /health reports it, and a
        # request that cannot be queued fails closed when it is added.
        try:
            os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
            if not os.path.exists(self.file_path):
                with open(self.file_path, "w") as f:
                    json.dump([], f)
        except OSError as exc:
            logger.error(f"Review queue file {self.file_path} cannot be created: {exc}")

    def _read_all(self) -> List[dict]:
        try:
            with open(self.file_path, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_all(self, data: List[dict]):
        # Atomic replace, so a crash mid-write cannot corrupt the queue.
        temp = f"{self.file_path}.tmp"
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(data[-2000:], f, indent=2)
        os.replace(temp, self.file_path)

    def add_item(self, ctx: RequestContext, session_id: str, system_msg: Optional[str] = None) -> ReviewQueueItem:
        item = ReviewQueueItem(
            id=str(uuid.uuid4()),
            request_id=ctx.request_id,
            session_id=session_id,
            original_input=ctx.llm_safe_input or ctx.raw_input,
            agentic_reason=ctx.g1_reasoning,
            agentic_confidence=ctx.g1_confidence,
            flags_summary=ctx.flags_compressed(),
            timestamp=time.time(),
            system_msg=system_msg,
            review_reason=ctx.review_reason or "Arbiter unsure",
        )
        r = redis_client()
        if r is not None:
            record = asdict(item)
            pipe = r.pipeline(transaction=True)
            pipe.hset(ITEMS, item.id, json.dumps(record))
            pipe.zadd(PENDING, {item.id: item.timestamp})
            pipe.zadd(ORDER, {item.id: item.timestamp})
            pipe.execute()
            self._trim_redis(r)
            return item
        with self.lock:
            data = self._read_all()
            data.append(asdict(item))
            self._write_all(data)
        return item

    # ── Redis layout: a hash of items, a sorted set of pending ids, a sorted set of all ids ──
    @staticmethod
    def _trim_redis(r) -> None:
        extra = r.zcard(ORDER) - MAX_ITEMS
        if extra > 0:
            old = r.zrange(ORDER, 0, extra - 1)
            if old:
                pipe = r.pipeline(transaction=True)
                pipe.zrem(ORDER, *old)
                pipe.zrem(PENDING, *old)
                pipe.hdel(ITEMS, *old)
                pipe.execute()

    @staticmethod
    def _close_redis(r, item_id: str, status: str, note: str = "") -> Optional[dict]:
        # ZREM returns 1 to exactly one caller, so two reviewers (or a reviewer and the timeout)
        # cannot both decide the same item.
        if r.zrem(PENDING, item_id) != 1:
            return None
        raw = r.hget(ITEMS, item_id)
        if raw is None:
            return None
        record = json.loads(raw)
        record.update(status=status, decided_at=time.time())
        if note or status != "timeout":
            record["reviewer_note"] = note
        r.hset(ITEMS, item_id, json.dumps(record))
        return record

    def get_pending_items(self) -> List[dict]:
        r = redis_client()
        if r is not None:
            ids = r.zrange(PENDING, 0, -1)
            return [json.loads(raw) for raw in (r.hmget(ITEMS, ids) if ids else []) if raw]
        with self.lock:
            data = self._read_all()
            return [d for d in data if d.get("status") == "pending"]

    def decide_item(self, item_id: str, decision: str, note: str = "") -> Optional[dict]:
        r = redis_client()
        if r is not None:
            return self._close_redis(r, item_id, decision, note)
        with self.lock:
            data = self._read_all()
            for d in data:
                if d["id"] == item_id and d.get("status") == "pending":
                    d["status"] = decision
                    d["reviewer_note"] = note
                    d["decided_at"] = time.time()
                    self._write_all(data)
                    return d
            return None

    def get_item(self, item_id: str) -> Optional[dict]:
        r = redis_client()
        if r is not None:
            raw = r.hget(ITEMS, item_id)
            return json.loads(raw) if raw else None
        with self.lock:
            data = self._read_all()
            for d in data:
                if d["id"] == item_id:
                    return d
            return None

    def timeout_stale_items(self, max_age_hours=24):
        now = time.time()
        r = redis_client()
        if r is not None:
            for item_id in r.zrangebyscore(PENDING, "-inf", now - max_age_hours * 3600):
                self._close_redis(r, item_id, "timeout")
            return
        with self.lock:
            data = self._read_all()
            changed = False
            for d in data:
                if d.get("status") == "pending":
                    if now - d.get("timestamp", now) > max_age_hours * 3600:
                        d["status"] = "timeout"
                        changed = True
            if changed:
                self._write_all(data)
                
review_queue = ReviewQueue()
