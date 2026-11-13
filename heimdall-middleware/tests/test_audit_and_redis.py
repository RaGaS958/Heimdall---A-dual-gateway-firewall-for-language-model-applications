"""Audit-log integrity, audit middleware coverage, calibration maths and real Redis."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path

import pytest

from core.cache.hot_cache import HotCache
from core.security.audit import AuditLog
from core.security.http import AdminAuditMiddleware


def _filled(tmp_path, count=5):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(count):
        log.record("POST /cache/flush", status=200, ip="10.0.0.1", target=str(i))
    return log


def _lines(log):
    return log.path.read_text(encoding="utf-8").splitlines()


def _write(log, lines):
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_clean_log_verifies(tmp_path):
    result = _filled(tmp_path).verify()
    assert result["ok"] and result["entries"] == 5 and result["authenticated"] == 5


def test_chain_continues_after_restart(tmp_path):
    log = _filled(tmp_path)
    reopened = AuditLog(str(log.path))
    reopened.record("POST /review/x/decide", status=200)
    assert reopened.verify()["ok"] and reopened.tail(1)[0]["seq"] == 6


def test_edited_line_is_detected(tmp_path):
    log = _filled(tmp_path)
    lines = _lines(log)
    row = json.loads(lines[2])
    row["status"] = 500
    lines[2] = json.dumps(row, sort_keys=True)
    _write(log, lines)
    result = log.verify()
    assert not result["ok"] and result["first_bad_line"] == 3


def test_deleted_line_is_detected(tmp_path):
    log = _filled(tmp_path)
    lines = _lines(log)
    del lines[2]
    _write(log, lines)
    result = log.verify()
    assert not result["ok"] and result["reason"] == "chain broken"


def test_swapped_lines_are_detected(tmp_path):
    log = _filled(tmp_path)
    lines = _lines(log)
    lines[1], lines[2] = lines[2], lines[1]
    _write(log, lines)
    assert not log.verify()["ok"]


def test_older_key_is_counted_not_failed(tmp_path, monkeypatch):
    log = _filled(tmp_path)
    from core.security import audit as module

    class Other:
        session_signing_key = "a-different-signing-key-for-this-test"
        audit_log_path = str(log.path)

    monkeypatch.setattr(module, "get_settings", lambda: Other())
    result = log.verify()
    assert result["ok"] and result["authenticated"] == 0 and result["signed_with_other_key"] == 5


def test_entry_never_holds_the_admin_key(tmp_path):
    log = _filled(tmp_path, 1)
    assert "admin" not in log.path.read_text(encoding="utf-8").lower()


def test_unwritable_path_does_not_raise():
    AuditLog("/proc/heimdall/audit.jsonl").record("POST /cache/flush", status=200)


def _run_middleware(tmp_path, monkeypatch, method, path, status):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    from core.security import http as module
    monkeypatch.setattr(module, "audit_log", log)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def send(message):
        pass

    scope = {"type": "http", "method": method, "path": path, "headers": [], "client": ("127.0.0.1", 1)}
    asyncio.run(AdminAuditMiddleware(app)(scope, None, send))
    return log.tail()


def test_admin_change_is_recorded(tmp_path, monkeypatch):
    rows = _run_middleware(tmp_path, monkeypatch, "POST", "/cache/flush", 200)
    assert rows[0]["action"] == "POST /cache/flush" and rows[0]["status"] == 200


def test_successful_admin_read_is_not_recorded(tmp_path, monkeypatch):
    assert _run_middleware(tmp_path, monkeypatch, "GET", "/review/queue", 200) == []


def test_refused_admin_read_is_recorded(tmp_path, monkeypatch):
    assert _run_middleware(tmp_path, monkeypatch, "GET", "/review/queue", 403)[0]["status"] == 403


def test_public_route_is_not_recorded(tmp_path, monkeypatch):
    assert _run_middleware(tmp_path, monkeypatch, "POST", "/chat", 200) == []


def _calibration():
    path = Path(__file__).resolve().parents[2] / "evaluation" / "calibrate_semantic.py"
    if not path.exists():
        pytest.skip("evaluation scripts are not in this checkout")
    spec = importlib.util.spec_from_file_location("calibrate_semantic", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_calibration_picks_lowest_threshold_within_limit():
    module = _calibration()
    rows = module.sweep([0.9, 0.85, 0.7], [0.75, 0.5])
    chosen = module.choose(rows, 0.0)
    assert chosen["threshold"] == 0.76 and chosen["caught"] == 2 and chosen["false_flags"] == 0


def test_calibration_returns_none_when_limit_unreachable():
    module = _calibration()
    assert module.choose(module.sweep([0.9], [1.0]), 0.0) is None


@pytest.mark.skipif(not os.getenv("HEIMDALL_TEST_REDIS_URL"), reason="set HEIMDALL_TEST_REDIS_URL to run")
def test_hot_cache_on_real_redis():
    cache = HotCache(use_fake=False, redis_url=os.environ["HEIMDALL_TEST_REDIS_URL"])
    cache.connect()
    assert cache.stats["type"] == "redis"
    cache._client.flushdb()
    assert cache.check("some exact text") is None
    cache.store("some exact text", {"verdict": "BLOCK"}, ttl=30)
    assert cache.check("some exact text")["verdict"] == "BLOCK"
    assert cache.check("some exact text", namespace="other") is None
    cache.block_session("sess-1", "repeated attacks", ttl=30)
    assert cache.is_session_blocked("sess-1") and 0 < cache.session_block_ttl("sess-1") <= 30
    assert not cache.is_session_blocked("sess-2")


# ── Immune approval workflow ──

import sqlite3  # noqa: E402

from fastapi import BackgroundTasks, HTTPException  # noqa: E402

from core.immune import api as immune_api  # noqa: E402
from core.immune import patch_engine  # noqa: E402
from core.immune.patch_engine import PatchProposal, PatchState  # noqa: E402
from core.immune.retest_engine import RetestResult  # noqa: E402


@pytest.fixture
def immune_store(tmp_path, monkeypatch):
    db = str(tmp_path / "immune.db")
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE proposals (id INTEGER PRIMARY KEY, seed_id TEXT, technique TEXT, status TEXT,
        proposal_state TEXT, campaign_id TEXT, proposal_id TEXT, proposed_fix_type TEXT, proposed_fix_data TEXT,
        defense_version INTEGER, bypass_payload TEXT)""")
    conn.execute("INSERT INTO proposals VALUES (1,'atk_001','json_wrap','PENDING','PENDING_APPROVAL','c1','P-1','PATTERN',"
                 "'{\"regex\": \"zzqq\", \"family\": \"X\"}',1,NULL)")
    conn.commit()
    conn.close()

    def get_db():
        connection = sqlite3.connect(db)
        connection.row_factory = sqlite3.Row
        return connection

    patterns = tmp_path / "patterns.yaml"
    patterns.write_text("patterns: []\n# a comment that must survive a rollback\n", encoding="utf-8")
    monkeypatch.setattr(immune_api, "get_db", get_db)
    monkeypatch.setattr(immune_api, "verify_admin", lambda *a, **k: None)
    monkeypatch.setattr(immune_api, "_g1_instance", object())
    monkeypatch.setattr(patch_engine, "DB_PATH", db)
    monkeypatch.setattr(patch_engine, "PATTERNS_PATH", str(patterns))
    monkeypatch.setattr(patch_engine, "KEYWORDS_PATH", str(tmp_path / "keywords.json"))
    monkeypatch.setattr(patch_engine, "DEFENSE_STATE_PATH", str(tmp_path / "defense.json"))
    return patterns


def _status():
    connection = sqlite3.connect(patch_engine.DB_PATH)
    try:
        return connection.execute("SELECT status FROM proposals WHERE id=1").fetchone()[0]
    finally:
        connection.close()


def test_reject_works_on_a_real_database_row(immune_store):
    result = asyncio.run(immune_api.reject_proposal("1", BackgroundTasks(), x_admin_key=""))
    assert result["status"] == "rejected" and _status() == "REJECTED"


def test_approve_refuses_when_the_bypass_text_is_gone(immune_store):
    with pytest.raises(HTTPException) as caught:
        asyncio.run(immune_api.approve_proposal("1", BackgroundTasks(), x_admin_key=""))
    assert caught.value.status_code == 409 and _status() == "PENDING"


class _Engine:
    def __init__(self):
        self.reloads = 0

    def load_patterns(self):
        self.reloads += 1


class _Gateway:
    def __init__(self):
        self.pattern = _Engine()


def _approve(monkeypatch, immune_store, outcome):
    gateway = _Gateway()
    monkeypatch.setattr(immune_api, "_g1_instance", gateway)

    async def related(*args, **kwargs):
        return []

    async def retest(**kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(immune_api, "_generate_related_payloads", related)
    monkeypatch.setattr(immune_api, "run_retest", retest)
    monkeypatch.setattr(immune_api, "store_retest_result", lambda result: None)
    proposal = PatchProposal(db_id=1, proposal_id="P-1", campaign_id="c1", seed_id="atk_001", technique="json_wrap",
                             patch_type="PATTERN", patch_data={"regex": "zzqq", "family": "X"},
                             affected_layer="L1", state=PatchState.APPROVED)
    asyncio.run(immune_api._approve_locked(proposal, 1, "the original bypass"))
    return gateway


def _result(**values):
    base = dict(proposal_id=1, campaign_id="c1", original_bypassed=False, original_verdict="BLOCK",
                verification_status="VERIFIED", benign_total=10)
    return RetestResult(**{**base, **values})


def test_verified_patch_stays(monkeypatch, immune_store):
    _approve(monkeypatch, immune_store, _result())
    assert "zzqq" in immune_store.read_text(encoding="utf-8") and _status() == "VERIFIED"


def test_patch_that_misses_the_bypass_is_rolled_back(monkeypatch, immune_store):
    before = immune_store.read_bytes()
    gateway = _approve(monkeypatch, immune_store,
                       _result(original_bypassed=True, verification_status="VERIFICATION_FAILED"))
    assert immune_store.read_bytes() == before and _status() == "VERIFICATION_FAILED" and gateway.pattern.reloads >= 1


def test_patch_that_blocks_benign_text_is_rolled_back(monkeypatch, immune_store):
    before = immune_store.read_bytes()
    _approve(monkeypatch, immune_store, _result(benign_blocked=1))
    assert immune_store.read_bytes() == before and _status() == "VERIFICATION_FAILED"


def test_crashed_retest_is_rolled_back(monkeypatch, immune_store):
    before = immune_store.read_bytes()
    _approve(monkeypatch, immune_store, RuntimeError("provider down"))
    assert immune_store.read_bytes() == before and _status() == "RETEST_FAILED"


# ── Shared rate limiter ──

def test_rate_limiter_local_window_and_backend_name():
    from core.security.rate_limit import SlidingWindowLimiter
    local = SlidingWindowLimiter()
    assert local.backend == "memory"
    assert [local.check("k", 2) for _ in range(3)][:2] == [None, None]
    assert local.check("k", 2) >= 1 and local.check("other", 2) is None


def test_rate_limiter_falls_back_when_redis_is_unreachable():
    from core.security.rate_limit import SlidingWindowLimiter
    limiter = SlidingWindowLimiter()
    assert limiter.use_redis("redis://127.0.0.1:1") is False
    assert limiter.backend == "memory" and limiter.check("k", 1) is None and limiter.check("k", 1) >= 1


@pytest.mark.skipif(not os.getenv("HEIMDALL_TEST_REDIS_URL"), reason="set HEIMDALL_TEST_REDIS_URL to run")
def test_two_limiters_share_one_window_on_real_redis():
    from core.security.rate_limit import SlidingWindowLimiter
    a, b = SlidingWindowLimiter(), SlidingWindowLimiter()
    assert a.use_redis(os.environ["HEIMDALL_TEST_REDIS_URL"]) and b.use_redis(os.environ["HEIMDALL_TEST_REDIS_URL"])
    a.reset()
    results = [(a if i % 2 else b).check("shared-client", 4, window=30.0) for i in range(6)]
    assert results[:4] == [None] * 4 and all(r and r >= 1 for r in results[4:])
    assert a.check("another-client", 4) is None
    a.reset()
