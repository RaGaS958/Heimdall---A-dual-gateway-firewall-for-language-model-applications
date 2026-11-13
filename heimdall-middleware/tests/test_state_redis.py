"""Review queue, reviewer labels and audit log kept in Redis (USE_FAKE_REDIS=false).

Runs against a real Redis: set HEIMDALL_TEST_REDIS_URL (for example redis://localhost:6379/15).
The database is flushed, so do not point it at one that holds data.
"""
import json
import os
import threading
import time

import pytest

from core.models import RequestContext
from core.state_store import state_store

URL = os.getenv("HEIMDALL_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set HEIMDALL_TEST_REDIS_URL to run")


@pytest.fixture
def redis_store():
    assert state_store.use_redis(URL)
    state_store.redis.flushdb()
    yield state_store.redis
    state_store.redis.flushdb()
    state_store.reset()


def held(text="hello", reason="Arbiter unsure (confidence 0.50)"):
    ctx = RequestContext(raw_input=text)
    ctx.review_reason = reason
    return ctx


def test_queue_round_trip_and_a_decision_is_final(redis_store, tmp_path):
    from core.review_queue import ReviewQueue
    queue = ReviewQueue(str(tmp_path / "unused.json"))
    item = queue.add_item(held(), "sid-1", system_msg="sys")
    assert [i["id"] for i in queue.get_pending_items()] == [item.id]
    assert not (tmp_path / "unused.json").read_text().strip("[] \n")  # nothing went to the file

    decided = queue.decide_item(item.id, "approved", "fine")
    assert decided["status"] == "approved" and decided["reviewer_note"] == "fine" and decided["system_msg"] == "sys"
    assert queue.decide_item(item.id, "rejected") is None
    assert queue.get_item(item.id)["status"] == "approved" and queue.get_pending_items() == []


def test_a_second_instance_sees_the_same_queue_and_only_one_reviewer_wins(redis_store, tmp_path):
    from core.review_queue import ReviewQueue
    a, b = ReviewQueue(str(tmp_path / "a.json")), ReviewQueue(str(tmp_path / "b.json"))
    item = a.add_item(held(), "sid")
    assert [i["id"] for i in b.get_pending_items()] == [item.id]

    wins = []
    threads = [threading.Thread(target=lambda q=q: wins.append(q.decide_item(item.id, "approved")))
               for q in [a, b] * 10]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(w is not None for w in wins) == 1


def test_stale_items_time_out(redis_store, tmp_path):
    from core import review_queue as rq
    queue = rq.ReviewQueue(str(tmp_path / "q.json"))
    old, new = queue.add_item(held(), "s1"), queue.add_item(held(), "s2")
    redis_store.zadd(rq.PENDING, {old.id: time.time() - 25 * 3600})
    queue.timeout_stale_items()
    assert queue.get_item(old.id)["status"] == "timeout"
    assert [i["id"] for i in queue.get_pending_items()] == [new.id]


def test_the_queue_keeps_only_the_newest_items(redis_store, tmp_path, monkeypatch):
    from core import review_queue as rq
    monkeypatch.setattr(rq, "MAX_ITEMS", 3)
    queue = rq.ReviewQueue(str(tmp_path / "q.json"))
    ids = [queue.add_item(held(f"t{i}"), "s").id for i in range(5)]
    assert redis_store.hlen(rq.ITEMS) == 3 and queue.get_item(ids[0]) is None and queue.get_item(ids[-1])


def test_audit_chain_from_two_instances_and_threads_stays_valid(redis_store, tmp_path):
    from core.security.audit import AuditLog
    a, b = AuditLog(str(tmp_path / "a.jsonl")), AuditLog(str(tmp_path / "b.jsonl"))
    threads = [threading.Thread(target=lambda log=log, i=i: log.record("review.decide", status=200, target=f"t{i}"))
               for i, log in enumerate([a, b] * 15)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = a.verify()
    assert result["ok"] and result["entries"] == 30 and result["last_seq"] == 30 and result["authenticated"] == 30
    assert b.tail(1)[0]["seq"] == 30 and not (tmp_path / "a.jsonl").exists()


def test_editing_an_audit_entry_in_redis_is_detected(redis_store, tmp_path):
    from core.security.audit import AUDIT_LIST, AuditLog
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for i in range(3):
        log.record("cache.flush", status=200)
    row = json.loads(redis_store.lindex(AUDIT_LIST, 1))
    row["status"] = 500
    redis_store.lset(AUDIT_LIST, 1, json.dumps(row, sort_keys=True))
    assert log.verify() == {"ok": False, "entries": 3, "first_bad_line": 2, "reason": "bad signature"}


def test_trimmed_audit_list_still_verifies(redis_store, tmp_path, monkeypatch):
    from core.security import audit
    monkeypatch.setattr(audit, "MAX_REDIS_ENTRIES", 5)
    log = audit.AuditLog(str(tmp_path / "a.jsonl"))
    for _ in range(8):
        log.record("cache.flush", status=200)
    result = log.verify()
    assert result["ok"] and result["entries"] == 5 and result["last_seq"] == 8


def test_reviewer_labels_go_to_redis(redis_store):
    import heimdall_app
    heimdall_app._append_label({"id": "x", "original_input": "text", "flags_summary": []}, "attack")
    assert json.loads(redis_store.lindex(heimdall_app.LABELS_KEY, -1))["label"] == "attack"


@pytest.mark.asyncio
async def test_health_and_review_routes_use_redis(redis_store, monkeypatch):
    from httpx import ASGITransport, AsyncClient
    import heimdall_app
    from core.review_queue import review_queue
    monkeypatch.setattr(heimdall_app.settings, "use_fake_redis", False)
    monkeypatch.setattr(heimdall_app.settings, "redis_url", URL)
    async with heimdall_app.app.router.lifespan_context(heimdall_app.app):
        item = review_queue.add_item(held(), "sid")
        headers = {"X-Admin-Key": heimdall_app.settings.admin_key}
        async with AsyncClient(transport=ASGITransport(app=heimdall_app.app), base_url="http://t") as c:
            health = (await c.get("/health")).json()["components"]
            queue = (await c.get("/review/queue", headers=headers)).json()["items"]
            audit = (await c.get("/audit/log", headers=headers)).json()
    assert health["state_storage"] == "redis" and health["rate_limiter"] == "redis"
    assert [i["id"] for i in queue] == [item.id]
    assert audit["verification"]["ok"]
