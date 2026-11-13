#!/usr/bin/env python3
"""Check Heimdall against the real model providers, using your own keys.

Part 1 calls Gemini, Groq and Mistral directly through the backend's own clients and
reports whether each key and model ID works. Part 2 sends development-corpus prompts
through a running stack and records what the firewall did.

    # Keys come from the environment, or from multi-llm-backend/.env
    python evaluation/live_provider_check.py                # providers only
    ./start_heimdall.sh                                     # in another terminal
    python evaluation/live_provider_check.py --stack --n 30

Part 2 reads only evaluation/corpora/dev_*.jsonl, never the Phase 12 held-out set, so
its numbers are a live smoke test and not a held-out result. Free tiers are slow, so
requests are paced with --delay. Keys are never printed or written to the result file.
"""
from __future__ import annotations

import argparse
from typing import Optional
import asyncio
import json
import math
import os
import random
import re
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
ROOT = HERE.parent
BACKEND = ROOT / "multi-llm-backend"
PROVIDERS = {"gemini": "GEMINI_API_KEY", "groq": "GROQ_API_KEY", "mistral": "MISTRAL_API_KEY"}
MODEL_LISTS = {
    "groq": ("https://api.groq.com/openai/v1/models", lambda key: {"Authorization": f"Bearer {key}"}),
    "mistral": ("https://api.mistral.ai/v1/models", lambda key: {"Authorization": f"Bearer {key}"}),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", lambda key: {"x-goog-api-key": key}),
}


def read_env_file(path: Path) -> dict:
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                values[name.strip()] = value.strip().strip("'\"")
    return values


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[key]")
    return re.sub(r"(gsk_|AIza)[A-Za-z0-9_\-]{10,}", "[key]", text)


def wilson(hits: int, total: int, z: float = 1.96) -> list[float]:
    if not total:
        return [0.0, 0.0]
    p = hits / total
    denominator = 1 + z * z / total
    centre = p + z * z / (2 * total)
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return [round((centre - margin) / denominator, 4), round((centre + margin) / denominator, 4)]


async def list_models(name: str, key: str) -> list[str]:
    url, headers = MODEL_LISTS[name]
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers(key))
        rows = response.json().get("data") or response.json().get("models") or []
        return sorted(str(r.get("id") or r.get("name", "")).replace("models/", "") for r in rows)
    except Exception:
        return []


async def check_providers(env: dict) -> dict:
    # clients.py reads model IDs from the environment at import time.
    os.environ.update({k: v for k, v in env.items() if k.endswith("_MODEL")})
    sys.path.insert(0, str(BACKEND))
    import clients

    calls = {"gemini": clients.call_gemini, "groq": clients.call_groq, "mistral": clients.call_mistral}
    secrets = [env.get(v, "") for v in PROVIDERS.values()]
    report = {}
    for name, variable in PROVIDERS.items():
        key = env.get(variable, "")
        if not key:
            report[name] = {"ok": False, "error": f"{variable} is not set"}
            print(f"  {name:8} not tested: {variable} is not set")
            continue
        # 400 tokens, not 20: reasoning models spend output tokens thinking before they answer.
        response = await calls[name]("Reply with the single word: ready", None, key, 400)
        entry = {"ok": response.ok, "model": response.model, "latency_ms": round(response.latency_ms, 1),
                 "reply": redact(response.text[:60], secrets), "error": redact(response.error[:300], secrets)}
        report[name] = entry
        if response.ok:
            print(f"  {name:8} ok      {response.model}  {response.latency_ms:.0f} ms  reply: {entry['reply']!r}")
        else:
            print(f"  {name:8} FAILED  {entry['error']}")
            if "404" in response.error or "not found" in response.error.lower():
                models = await list_models(name, key)
                entry["available_models"] = models
                print(f"           Set {name.upper()}_MODEL to one of: {', '.join(models[:12]) or 'unknown'}")
    return report


def load_corpus(name: str) -> list[dict]:
    with (HERE / "corpora" / name).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def send(client: httpx.Client, base: str, message: str, admin_key: str = "") -> dict:
    """One prompt in a fresh session, so one block cannot lock the next prompt out.
    With the admin key the response carries per-layer diagnostics (no prompt or reply text)."""
    for attempt in range(4):
        session = client.post(f"{base}/session/init", json={})
        if session.status_code == 429:
            time.sleep(float(session.headers.get("retry-after", 5)))
            continue
        session.raise_for_status()
        token = session.json()["session_token"]
        headers = {"X-Heimdall-Session": token, **({"X-Admin-Key": admin_key} if admin_key else {})}
        response = client.post(f"{base}/chat", json={"message": message}, headers=headers)
        if response.status_code == 429:
            time.sleep(float(response.headers.get("retry-after", 5)))
            continue
        return {"http": response.status_code, **response.json()}
    return {"http": 429, "blocked": False, "error": "rate limited after retries"}


def model_judge(env: dict, attack: str, reply: str) -> dict:
    """Ask Groq whether an unclear reply did what the attacker wanted. Costs one call per reply."""
    from attack_judge import JUDGE_SYSTEM, judge_prompt, parse_judgement
    key = env.get("GROQ_API_KEY", "")
    if not key:
        return {"outcome": "unclear", "how": "no GROQ_API_KEY for the judge"}
    model = env.get("GROQ_MODEL", "openai/gpt-oss-20b")
    body = {"model": model, "temperature": 0, "max_completion_tokens": 400,
            "messages": [{"role": "system", "content": JUDGE_SYSTEM}, {"role": "user", "content": judge_prompt(attack, reply)}]}
    if model.startswith("openai/gpt-oss"):
        body["reasoning_effort"] = "low"
    try:
        r = httpx.post("https://api.groq.com/openai/v1/chat/completions", json=body, timeout=40,
                       headers={"Authorization": f"Bearer {key}"})
        if r.status_code != 200:
            return {"outcome": "unclear", "how": f"judge HTTP {r.status_code}"}
        verdict = parse_judgement(r.json()["choices"][0]["message"].get("content") or "")
        return verdict or {"outcome": "unclear", "how": "judge reply unreadable"}
    except httpx.HTTPError as exc:
        return {"outcome": "unclear", "how": f"judge error {type(exc).__name__}"}


def _layer_counts(rows) -> dict:
    """kind -> layer -> count, from admin diagnostics. Empty when the run had no admin key."""
    out: dict = {}
    for r in rows:
        for f in (r.get("diagnostics") or {}).get("flags", []):
            bucket = out.setdefault(r["kind"], {})
            bucket[f["layer"]] = bucket.get(f["layer"], 0) + 1
    return out


def _removed_counts(rows) -> dict:
    out: dict = {}
    for r in rows:
        for label, count in ((r.get("diagnostics") or {}).get("g2_removed") or {}).items():
            out[label] = out.get(label, 0) + count
    return out


def check_stack(base: str, n: int, delay: float, seed: int, env: Optional[dict] = None, judge: bool = False,
                admin_key: str = "") -> dict:
    from attack_judge import judge_reply
    client = httpx.Client(timeout=90.0)
    health = client.get(f"{base}/health").json()
    print(f"  stack {health.get('version')}  arbiter: {health['components']['agentic']}  "
          f"backend: {health['components']['multi_llm_backend']}  L3: {health['components']['l3_mode']}")

    rng = random.Random(seed)
    attacks = rng.sample(load_corpus("dev_attacks.jsonl"), n)
    benign = rng.sample(load_corpus("dev_benign.jsonl"), n)
    rows = []
    for kind, items in (("attack", attacks), ("benign", benign)):
        for index, item in enumerate(items, 1):
            result = send(client, base, item["text"], admin_key)
            rows.append({"kind": kind, "family": item.get("family"), "http": result.get("http"),
                         "blocked": bool(result.get("blocked")), "sanitized": bool(result.get("sanitized")),
                         "verdict_g1": result.get("verdict_g1"), "verdict_g2": result.get("verdict_g2"),
                         "degraded": bool(result.get("degraded")), "arbiter_tokens": result.get("agentic_tokens", 0),
                         "status": result.get("status"), "latency_ms": result.get("latency_total_ms"),
                         "answered": bool(result.get("reply")) and result.get("http") == 200,
                         "flags": result.get("flags_count"), "reason": (result.get("reason") or "")[:160],
                         "input_flags": result.get("input_flags"), "output_flags": result.get("output_flags"),
                         "diagnostics": result.get("diagnostics"),
                         "g1_ms": result.get("latency_g1_ms"),
                         # Per provider, so a slow or failing one is visible. Reply text is not stored.
                         "providers": {name: {"ok": bool(r.get("ok")), "ms": r.get("latency_ms"), "error": (r.get("error") or "")[:80],
                                              "reply_chars": len(r.get("text") or "")}
                                       for name, r in (result.get("llm_responses") or {}).items() if isinstance(r, dict)}})
            row = rows[-1]
            row["held"] = result.get("status") == "pending"
            if kind == "attack" and result.get("http") == 200 and not row["blocked"] and not row["held"]:
                # The reply text is judged here and then dropped; only the outcome is kept.
                final = judge_reply(item["text"], result.get("reply"))
                if final["outcome"] == "unclear" and judge:
                    final = {**model_judge(env or {}, item["text"], result.get("reply") or ""), "reply_chars": final["reply_chars"]}
                row["attack_outcome"] = final
                row["raw_model_outcome"] = {name: judge_reply(item["text"], r.get("text"))["outcome"]
                                            for name, r in (result.get("llm_responses") or {}).items() if isinstance(r, dict)}
            print(f"\r  {kind}: {index}/{len(items)}", end="", flush=True)
            time.sleep(delay)
        print()

    def stopped(row):
        # A request held for review is not answered until a person approves it.
        return row["blocked"] or row.get("held") or row["http"] in (403, 423)

    attack_rows = [r for r in rows if r["kind"] == "attack" and r["http"] != 429]
    # A 502 means every provider failed, so Heimdall never returned a verdict for that prompt.
    # Counting it as "not falsely blocked" would flatter the result, so it leaves the denominator.
    benign_rows = [r for r in rows if r["kind"] == "benign" and r["http"] not in (429, 502)]
    stopped_attacks = sum(map(stopped, attack_rows))
    false_blocks = sum(r["blocked"] or r["http"] in (403, 423) for r in benign_rows)
    passed = [r for r in attack_rows if not stopped(r)]
    outcomes = {}
    for r in passed:
        label = (r.get("attack_outcome") or {}).get("outcome", "not_judged")
        outcomes[label] = outcomes.get(label, 0) + 1
    provider_failures = sum(r["http"] == 502 for r in rows)
    summary = {
        "attacks_stopped": stopped_attacks, "attacks_sent": len(attack_rows),
        "attack_stop_rate_ci95": wilson(stopped_attacks, len(attack_rows)),
        "benign_false_blocks": false_blocks, "benign_sent": len(benign_rows),
        "benign_without_verdict": sum(r["kind"] == "benign" and r["http"] == 502 for r in rows),
        "attacks_blocked_without_arbiter_tokens_but_slow": sum(
            1 for r in rows if r["kind"] == "attack" and r["blocked"] and not r["arbiter_tokens"] and (r["latency_ms"] or 0) > 400),
        "false_block_rate_ci95": wilson(false_blocks, len(benign_rows)),
        "requests_where_arbiter_ran": sum(bool(r["arbiter_tokens"]) for r in rows),
        "degraded_responses": sum(r["degraded"] for r in rows),
        "provider_failures": provider_failures,
        "rate_limited": sum(r["http"] == 429 for r in rows),
        "requests_over_20s": sum((r["latency_ms"] or 0) > 20000 for r in rows),
        "provider_errors": {name: sum(1 for r in rows if name in r["providers"] and not r["providers"][name]["ok"])
                            for name in sorted({n for r in rows for n in r["providers"]})},
        "arbiter_passed_attacks": sum(1 for r in rows if r["kind"] == "attack" and r["arbiter_tokens"] and not stopped(r)),
        "attacks_held_for_review": sum(1 for r in attack_rows if r.get("held")),
        "benign_held_for_review": sum(1 for r in benign_rows if r.get("held")),
        # Of the attacks that got through: did the answer the user received do what the attacker wanted?
        "passed_attack_outcomes": outcomes,
        "attacks_that_worked": outcomes.get("succeeded", 0),
        "attack_success_rate_ci95": wilson(outcomes.get("succeeded", 0), len(attack_rows)),
        # Input flags are Gateway 1 signals on the prompt; output flags are Gateway 2 findings on the answer.
        "benign_with_input_flags": sum(1 for r in benign_rows if r.get("input_flags")),
        "benign_answers_changed_by_g2": sum(1 for r in benign_rows if r.get("verdict_g2") == "SANITIZE"),
        "flag_layers": _layer_counts(rows),
        "g2_removed_on_benign": _removed_counts(benign_rows),
    }
    if summary["benign_without_verdict"]:
        print(f"  {summary['benign_without_verdict']} benign prompts got no verdict (every provider failed) and are excluded")
    print(f"  attacks stopped {stopped_attacks}/{len(attack_rows)}, benign falsely blocked "
          f"{false_blocks}/{len(benign_rows)}, arbiter ran on {summary['requests_where_arbiter_ran']}, "
          f"provider failures {provider_failures}")
    print(f"  held for review: {summary['attacks_held_for_review']} attacks, {summary['benign_held_for_review']} benign "
          f"(benign holds are not counted as false blocks, but each one waits for a person)")
    print(f"  of {len(passed)} attacks that got through: {outcomes or 'none'}; attacks that worked: {summary['attacks_that_worked']}/{len(attack_rows)}")
    if summary["flag_layers"]:
        print(f"  signals by layer: {summary['flag_layers']}")
        print(f"  benign: {summary['benign_with_input_flags']} prompts flagged on input, "
              f"{summary['benign_answers_changed_by_g2']} answers changed by Gateway 2 ({summary['g2_removed_on_benign'] or 'nothing removed'})")
    print(f"  slow requests (over 20 s): {summary['requests_over_20s']}, provider errors: {summary['provider_errors']}, "
          f"attacks the arbiter let through: {summary['arbiter_passed_attacks']}")
    return {"health": health, "summary": summary, "cases": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stack", action="store_true", help="also test a running middleware")
    parser.add_argument("--skip-providers", action="store_true")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--n", type=int, default=20, help="attacks and benign prompts to send, each")
    parser.add_argument("--delay", type=float, default=2.0, help="seconds between prompts")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default="")
    parser.add_argument("--judge", action="store_true",
                        help="ask Groq to judge replies the fixed checks cannot classify (one call each)")
    args = parser.parse_args()

    env = {**read_env_file(BACKEND / ".env"), **{k: v for k, v in os.environ.items() if k in PROVIDERS.values()
                                                  or k.endswith("_MODEL")}}
    # The admin key only adds diagnostics to each response; it changes no verdict in production mode.
    admin_key = os.environ.get("ADMIN_KEY") or read_env_file(ROOT / ".env").get("ADMIN_KEY", "")
    if args.stack and not admin_key:
        print("  (no ADMIN_KEY in the environment or ./.env: per-layer diagnostics will be missing)")
    result = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "corpus": "development only",
              "diagnostics": bool(admin_key)}
    if not args.skip_providers:
        print("Providers")
        result["providers"] = asyncio.run(check_providers(env))
    if args.stack:
        print("Stack")
        try:
            result["stack"] = check_stack(args.url.rstrip("/"), args.n, args.delay, args.seed, env, args.judge, admin_key)
        except httpx.HTTPError as exc:
            print(f"  Could not reach the stack at {args.url}: {exc}. Start it with ./start_heimdall.sh")
            return 2

    out = Path(args.out or HERE / "results" / f"live_check_{time.strftime('%Y%m%d_%H%M%S')}.json")
    text = redact(json.dumps(result, indent=2), [env.get(v, "") for v in PROVIDERS.values()] + [admin_key])
    out.write_text(text, encoding="utf-8")
    print(f"Saved {out}")
    providers_ok = all(p.get("ok") for p in result.get("providers", {}).values())
    return 0 if providers_ok or args.skip_providers else 1


if __name__ == "__main__":
    sys.exit(main())
