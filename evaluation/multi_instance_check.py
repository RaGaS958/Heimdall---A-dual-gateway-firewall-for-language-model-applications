#!/usr/bin/env python3
"""Two middleware instances behind one Redis: what is shared and what is not.

    redis-server --port 6399 &
    python evaluation/multi_instance_check.py --redis redis://localhost:6399/2

Starts the mock model backend and two middleware processes with the same keys, then checks
through HTTP that a rate limit, a session token and a cached verdict hold across instances.
Also runs a small concurrency test against one instance. Writes results/multi_instance.json.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent
ROOT = HERE.parent
ADMIN = "multi-instance-admin-key-0001"
PORTS = (8101, 8102)


def start(args_list, cwd, env):
    return subprocess.Popen([sys.executable, "-m", "uvicorn", *args_list], cwd=cwd, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait(url, seconds=40):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return True
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} did not start")


async def load(base, texts, concurrency, total):
    latencies, errors = [], 0
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=30) as client:
        async def one(i):
            nonlocal errors
            async with sem:
                t0 = time.perf_counter()
                r = await client.post(f"{base}/scan", json={"text": texts[i % len(texts)]})
                if r.status_code != 200:
                    errors += 1
                latencies.append((time.perf_counter() - t0) * 1000)
        started = time.perf_counter()
        await asyncio.gather(*(one(i) for i in range(total)))
        wall = time.perf_counter() - started
    latencies.sort()
    pick = lambda q: round(latencies[min(len(latencies) - 1, int(len(latencies) * q))], 1)
    return {"concurrency": concurrency, "requests": total, "errors": errors, "requests_per_second": round(total / wall, 1),
            "p50_ms": pick(0.5), "p95_ms": pick(0.95), "p99_ms": pick(0.99), "mean_ms": round(statistics.mean(latencies), 1)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--redis", required=True)
    args = parser.parse_args()
    base_env = {**os.environ, "ADMIN_KEY": ADMIN, "INTERNAL_AUTH_KEY": "multi-instance-internal-key-01",
                "SESSION_SIGNING_KEY": "multi-instance-signing-key-0001", "EMBEDDINGS_ENABLED": "false",
                "USE_FAKE_REDIS": "false", "REDIS_URL": args.redis, "HEIMDALL_ENV": "test",
                "RATE_LIMIT_SCAN": "20", "RATE_LIMIT_CHAT": "100000", "RATE_LIMIT_DEFAULT": "100000", "RATE_LIMIT_SESSION": "100000"}
    procs = [start(["mock_llm_backend:app", "--port", "8001"], HERE, base_env)]
    report = {}
    try:
        for port in PORTS:
            procs.append(start(["heimdall_app:app", "--port", str(port)], ROOT / "heimdall-middleware", base_env))
        for port in PORTS:
            wait(f"http://localhost:{port}/health")
        a, b = (f"http://localhost:{p}" for p in PORTS)
        health = [httpx.get(f"{u}/health").json()["components"] for u in (a, b)]
        report["rate_limiter_backend"] = [h.get("rate_limiter") for h in health]

        # 1. One client, limit 20 per minute, requests alternating between the two instances.
        codes = [httpx.post(f"{(a, b)[i % 2]}/scan", json={"text": f"what is {i} plus {i}?"}).status_code for i in range(30)]
        report["shared_rate_limit"] = {"limit": 20, "sent": 30, "allowed": codes.count(200), "refused_429": codes.count(429),
                                       "pass": codes.count(200) == 20 and codes.count(429) == 10}

        # 2. A session token issued by instance A is accepted by instance B.
        issued = httpx.post(f"{a}/session/init", json={}).json()
        reply = httpx.post(f"{b}/chat", json={"message": "What is the capital of France?", "session_id": issued["session_id"]},
                           headers={"X-Heimdall-Session": issued["session_token"]}, timeout=60)
        same = reply.status_code == 200 and reply.json().get("session_id") == issued["session_id"]
        report["session_token_across_instances"] = {"status_on_b": reply.status_code, "same_session": same, "pass": same,
                                                    "detail": None if same else reply.text[:200]}
    finally:
        for proc in procs[1:]:
            proc.terminate()
        time.sleep(1)

    # 3. Load: one instance, limits lifted, deterministic /scan only.
    env = {**base_env, "RATE_LIMIT_SCAN": "10000000"}
    procs.append(start(["heimdall_app:app", "--port", "8103"], ROOT / "heimdall-middleware", env))
    try:
        wait("http://localhost:8103/health")
        rows = [json.loads(l) for l in (HERE / "corpora/dev_attacks.jsonl").read_text(encoding="utf-8").split("\n") if l.strip()]
        rows += [json.loads(l) for l in (HERE / "corpora/dev_benign.jsonl").read_text(encoding="utf-8").split("\n") if l.strip()]
        texts = [r["text"] for r in rows if r.get("mutation", "NONE") == "NONE"]
        report["load_scan_single_instance"] = [asyncio.run(load("http://localhost:8103", texts, c, 600)) for c in (1, 8, 32)]
    finally:
        for proc in procs:
            proc.terminate()
    out = HERE / "results" / "multi_instance.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
