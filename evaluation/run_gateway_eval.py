#!/usr/bin/env python3
"""Paired deterministic evaluation of two middleware checkouts on identical inputs.

    python evaluation/run_gateway_eval.py --suites dev
    python evaluation/run_gateway_eval.py --suites heldout
    python evaluation/run_gateway_eval.py --suites extdev     # external benchmark, readable half
    python evaluation/run_gateway_eval.py --suites exttest    # external benchmark, sealed half: counts only

Decision rule is the Phase 12 "P2-0" condition: the arbiter is unavailable, so a hard
signal means BLOCK (fail closed) and anything else reaches the model. Embeddings are
off unless the host can load them, so L3 is measured in its lexical or keyword mode.

This measures gateway interception. It does not measure end-to-end attack success on
a live model, and it says nothing about the arbiter's semantic accuracy.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent


def jsonl(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").split("\n") if l.strip()]


def suite_cases(kind, phase12, known_dir):
    if kind in ("extdev", "exttest"):
        return jsonl(HERE / "external" / f"ext_{kind[3:]}.jsonl")
    if kind == "dev":
        rows = []
        for i, r in enumerate(jsonl(HERE / "corpora/dev_attacks.jsonl")):
            rows.append({"id": f"dev_a{i}", "suite": "dev", "label": "attack", "group": r.get("mutation", "NONE"), "text": r["text"]})
        for i, r in enumerate(jsonl(HERE / "corpora/dev_benign.jsonl")):
            rows.append({"id": f"dev_b{i}", "suite": "dev", "label": "benign", "group": "hard" if r["hard"] else "plain", "text": r["text"]})
        v2 = HERE / "corpora/dev_benign_v2.jsonl"
        for i, r in enumerate(jsonl(v2) if v2.exists() else []):
            rows.append({"id": f"dev_c{i}", "suite": "dev", "label": "benign", "group": f"hard_v2_{r['split']}", "text": r["text"]})
        return rows
    rows = []
    for r in json.loads((phase12 / "attack_manifest.json").read_text(encoding="utf-8")):
        rows.append({"id": f"p12_{len(rows)}", "suite": "phase12", "label": "attack",
                     "group": "ORIGINAL" if r.get("strategy") == "ORIGINAL" else "UNSEEN", "text": r["text"]})
    for r in json.loads((phase12 / "benign_manifest.json").read_text(encoding="utf-8")):
        rows.append({"id": f"p12_{len(rows)}", "suite": "phase12", "label": "benign", "group": "benign", "text": r["text"]})
    for r in json.loads((known_dir / "known_attacks.json").read_text(encoding="utf-8")):
        if r.get("id") != "atk_dummy_bypass":
            rows.append({"id": f"v1_{r['id']}", "suite": "heimdall_v1", "label": "attack", "group": r.get("family", ""), "text": r["text"]})
    for r in json.loads((known_dir / "benign_corpus.json").read_text(encoding="utf-8")):
        rows.append({"id": f"v1_{r['id']}", "suite": "heimdall_v1", "label": "benign", "group": "benign", "text": r["text"]})
    return rows


def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - m) / d), min(1.0, (c + m) / d))


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def probe(python, middleware, suite_file, out):
    subprocess.run([python, str(HERE / "_probe.py"), str(Path(middleware).resolve()), str(suite_file), str(out)], check=True)
    return {r["id"]: r for r in json.load(open(out))}


def summarize(before, after, label):
    ids = sorted(before)
    n = len(ids)
    out = {"n": n, "before": sum(before[i]["intercepted"] for i in ids), "after": sum(after[i]["intercepted"] for i in ids)}
    b_to_a = [i for i in ids if not before[i]["intercepted"] and after[i]["intercepted"]]
    a_to_b = [i for i in ids if before[i]["intercepted"] and not after[i]["intercepted"]]
    out["gained"], out["lost"] = len(b_to_a), len(a_to_b)
    out["mcnemar_p"] = mcnemar_exact(len(b_to_a), len(a_to_b))
    out["before_ci"], out["after_ci"] = wilson(out["before"], n), wilson(out["after"], n)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--before", default=str(HERE / "baseline_v2_middleware"))
    p.add_argument("--after", default=str(ROOT / "heimdall-middleware"))
    p.add_argument("--suites", choices=["dev", "heldout", "extdev", "exttest"], required=True)
    p.add_argument("--tag", default="", help="suffix for the result file, e.g. run0_pre_tuning")
    p.add_argument("--phase12", default=str(ROOT / "research/phase12/datasets"))
    p.add_argument("--out", default=str(HERE / "results"))
    p.add_argument("--python", default=sys.executable)
    args = p.parse_args()

    known = Path(args.after) / "data"
    cases = suite_cases(args.suites, Path(args.phase12), known)
    with tempfile.TemporaryDirectory() as tmp:
        suite_file = Path(tmp) / "suite.jsonl"
        suite_file.write_text("\n".join(json.dumps(c, ensure_ascii=False) for c in cases), encoding="utf-8")
        before = probe(args.python, args.before, suite_file, Path(tmp) / "b.json")
        after = probe(args.python, args.after, suite_file, Path(tmp) / "a.json")

    report = {"suite": args.suites, "decision_rule": "hard signal => BLOCK (arbiter unavailable)", "groups": {}}
    keys = sorted({(c["suite"], c["label"]) for c in cases})
    for suite, label in keys:
        ids = [c["id"] for c in cases if c["suite"] == suite and c["label"] == label]
        report["groups"][f"{suite}/{label}"] = summarize({i: before[i] for i in ids}, {i: after[i] for i in ids}, label)
    groups = sorted({(c["suite"], c["label"], c["group"]) for c in cases})
    report["by_group"] = {}
    for suite, label, group in groups:
        ids = [c["id"] for c in cases if (c["suite"], c["label"], c["group"]) == (suite, label, group)]
        report["by_group"][f"{suite}/{label}/{group}"] = summarize({i: before[i] for i in ids}, {i: after[i] for i in ids}, label)
    for name, res in (("before", before), ("after", after)):
        lat = sorted(r["latency_ms"] for r in res.values())
        report[f"latency_{name}"] = {"p50_ms": statistics.median(lat), "p95_ms": lat[int(len(lat) * 0.95)], "max_ms": lat[-1]}

    Path(args.out).mkdir(exist_ok=True, parents=True)
    out = Path(args.out) / f"gateway_eval_{args.suites}{'_' + args.tag if args.tag else ''}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    misses = [c for c in cases if c["label"] == "attack" and not after[c["id"]]["intercepted"]]
    fps = [c for c in cases if c["label"] == "benign" and after[c["id"]]["intercepted"]]
    if args.suites in ("dev", "extdev"):  # never print or store held-out or sealed-test text
        Path(args.out, f"{args.suites}_misses.json").write_text(json.dumps({"misses": misses, "false_positives": fps}, indent=1, ensure_ascii=False), encoding="utf-8")
    for key, v in report["groups"].items():
        print(f"{key:28s} n={v['n']:4d} before={v['before']:4d} after={v['after']:4d} gained={v['gained']:3d} lost={v['lost']:3d} p={v['mcnemar_p']:.2e}")
    print(report["latency_before"], report["latency_after"])


if __name__ == "__main__":
    main()
