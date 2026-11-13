import json
import time
import os
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from core.models import RequestContext
import threading

QUEUE_FILE = "data/review_queue.json"

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

class ReviewQueue:
    def __init__(self, file_path=QUEUE_FILE):
        self.file_path = file_path
        self.lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def _read_all(self) -> List[dict]:
        try:
            with open(self.file_path, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_all(self, data: List[dict]):
        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=2)

    def add_item(self, ctx: RequestContext, session_id: str, system_msg: Optional[str] = None) -> ReviewQueueItem:
        item = ReviewQueueItem(
            id=str(uuid.uuid4()),
            request_id=ctx.request_id,
            session_id=session_id,
            original_input=ctx.raw_input,
            agentic_reason=ctx.g1_reasoning,
            agentic_confidence=ctx.g1_confidence,
            flags_summary=ctx.flags_compressed(),
            timestamp=time.time(),
            system_msg=system_msg
        )
        with self.lock:
            data = self._read_all()
            data.append(asdict(item))
            self._write_all(data)
        return item

    def get_pending_items(self) -> List[dict]:
        with self.lock:
            data = self._read_all()
            return [d for d in data if d.get("status") == "pending"]

    def decide_item(self, item_id: str, decision: str, note: str = "") -> Optional[dict]:
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
        with self.lock:
            data = self._read_all()
            for d in data:
                if d["id"] == item_id:
                    return d
            return None

    def timeout_stale_items(self, max_age_hours=24):
        now = time.time()
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
