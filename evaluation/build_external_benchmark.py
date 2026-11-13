#!/usr/bin/env python3
"""Build the Phase 15 external benchmark from third-party data nobody on this project wrote.

    git clone --depth 1 https://github.com/HumanCompatibleAI/tensor-trust-data
    git clone --depth 1 https://github.com/tatsu-lab/stanford_alpaca
    pip download garak==0.17.1 --no-deps -d garak_whl && unzip -q garak_whl/*.whl -d garak_src
    python evaluation/build_external_benchmark.py --tensor-trust tensor-trust-data \\
        --garak garak_src --alpaca stanford_alpaca

Attacks: Tensor Trust hijacking and extraction robustness benchmarks (player-written attacks),
and garak's in-the-wild jailbreaks, DAN prompts and system-prompt extraction attacks.
Benign: a hash-selected sample of Stanford Alpaca instructions.

Every prompt is assigned to `dev` or `test` by the SHA-256 of its text, so the split cannot be
chosen. Rule work may read `ext_dev.jsonl`. Nothing may print or open `ext_test.jsonl` except
the scorer, which reports counts only. The data is not redistributed with this project (Alpaca
is CC BY-NC 4.0; check each source's terms); the manifest records hashes so a rebuild can be verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

OUT = Path(__file__).parent / "external"
BENIGN_SAMPLE = 2000
MAX_CHARS = 8000  # the gateway's own request limit is far below the longest scraped jailbreaks


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").split("\n") if line.strip()]


def collect(args):
    rows = []
    tt = Path(args.tensor_trust) / "benchmarks"
    for name, group in (("hijacking-robustness/v1/hijacking_robustness_dataset.jsonl", "tensortrust_hijacking"),
                        ("extraction-robustness/v1/extraction_robustness_dataset.jsonl", "tensortrust_extraction")):
        rows += [("attack", group, r["attack"]) for r in jsonl(tt / name)]
    data = Path(args.garak) / "garak" / "data"
    rows += [("attack", "garak_inthewild_jailbreak", t) for t in json.loads((data / "inthewild_jailbreak_llms.json").read_text(encoding="utf-8"))]
    for f in sorted((data / "dan").glob("*.json")):
        rows += [("attack", "garak_dan", t) for t in json.loads(f.read_text(encoding="utf-8")) if isinstance(t, str)]
    for group, items in json.loads((data / "sysprompt_extraction" / "attacks.json").read_text(encoding="utf-8")).items():
        rows += [("attack", "garak_sysprompt_extraction", t) for t in items]
    alpaca = json.loads((Path(args.alpaca) / "alpaca_data.json").read_text(encoding="utf-8"))
    benign = sorted({(r["instruction"] + ("\n\n" + r["input"] if r.get("input") else "")).strip() for r in alpaca}, key=sha)[:BENIGN_SAMPLE]
    rows += [("benign", "alpaca", t) for t in benign]
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tensor-trust", required=True)
    p.add_argument("--garak", required=True)
    p.add_argument("--alpaca", required=True)
    args = p.parse_args()

    seen, out, dropped = set(), {"dev": [], "test": []}, Counter()
    for label, group, text in collect(args):
        text = (text or "").strip()
        digest = sha(text)
        if not text or digest in seen:
            dropped["empty_or_duplicate"] += 1
            continue
        if len(text) > MAX_CHARS:
            dropped["over_length"] += 1
            continue
        seen.add(digest)
        split = "dev" if int(digest[:2], 16) % 2 == 0 else "test"
        out[split].append({"id": f"ext_{digest[:12]}", "suite": f"ext_{split}", "label": label, "group": group, "text": text})

    OUT.mkdir(exist_ok=True)
    manifest = {"sources": {"tensor_trust": "HumanCompatibleAI/tensor-trust-data benchmarks v1", "garak": "garak 0.17.1 data files", "alpaca": "tatsu-lab/stanford_alpaca alpaca_data.json"},
                "split_rule": "first byte of sha256(text) even => dev, odd => test", "dropped": dict(dropped), "splits": {}}
    for split, rows in out.items():
        rows.sort(key=lambda r: r["id"])
        body = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
        (OUT / f"ext_{split}.jsonl").write_text(body, encoding="utf-8")
        manifest["splits"][split] = {"sha256": sha(body), "counts": dict(sorted(Counter(f"{r['label']}/{r['group']}" for r in rows).items()))}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
