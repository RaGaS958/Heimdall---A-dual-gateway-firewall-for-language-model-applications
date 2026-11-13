"""
HEIMDALL Phase 2 — Immune Event Emitter

All events include a campaignId so SSE subscribers can filter by active campaign.
Old campaign events do not contaminate new campaign UI state.

Event shape:
  {
    "type": "BYPASS_DETECTED",
    "campaignId": "cmp-abc123",
    "data": { ... }
  }
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional


class EventEmitter:
    """
    In-process pub/sub for immune campaign events.

    Thread safety: designed for asyncio — do not call publish() from
    sync threads; use asyncio.run_coroutine_threadsafe if needed.
    """

    def __init__(self):
        self._queues: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        """Return a new subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber queue (call from SSE cleanup)."""
        try:
            self._queues.remove(q)
        except ValueError:
            pass  # Already removed — safe to ignore

    async def publish(
        self,
        event_type: str,
        data: Optional[dict] = None,
        campaign_id: Optional[str] = None,
    ) -> None:
        """
        Broadcast an event to all active subscribers.

        campaignId is included in every event so the frontend can filter
        events to the currently active campaign only.
        """
        if data is None:
            data = {}
        payload = {
            "type": event_type,
            "campaignId": campaign_id or "",
            "data": data,
        }
        json_payload = json.dumps(payload)
        for q in list(self._queues):  # snapshot — safe during iteration
            try:
                q.put_nowait(json_payload)
            except asyncio.QueueFull:
                pass  # Drop to prevent slow subscriber from blocking campaign

    @property
    def subscriber_count(self) -> int:
        return len(self._queues)


# Module-level singleton — imported by api.py and campaign_runner.py
immune_events = EventEmitter()
