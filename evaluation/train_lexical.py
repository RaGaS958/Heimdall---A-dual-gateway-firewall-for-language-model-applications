#!/usr/bin/env python3
"""Train the L3b hashed char n-gram classifier and export it.

    python evaluation/train_lexical.py --middleware heimdall-middleware

Training data: the authored development corpus plus the *development half* of the external
benchmark (evaluation/external/ext_dev.jsonl), when it has been built. The sealed external
half and the Phase 12 held-out set are never read here.

Two thresholds are chosen from out-of-fold predictions (5-fold), so each example is scored by
a model that never saw it:
  flag   the score that raises a soft signal (severity 6)
  block  the score that counts as a hard signal on its own (severity 7); set where no benign
         out-of-fold example scores higher, plus a margin

Benign examples are weighted up: a false block costs a real user, while a missed attack still
has to get past L1, L4, spotlighting and Gateway 2. Needs scikit-learn at training time only.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import zlib
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

HERE = Path(__file__).parent


def load(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--middleware", default=str(HERE.parent / "heimdall-middleware"))
    parser.add_argument("--dim", type=int, default=32768)
    parser.add_argument("--margin", type=float, default=0.02)
    parser.add_argument("--no-external", action="store_true", help="train on the authored corpus only, for example if the external data's licences do not suit your use")
    parser.add_argument("--min-block", type=float, default=0.95, help="floor for the block threshold; benign text in production is more varied than any corpus")
    args = parser.parse_args()
    sys.path.insert(0, args.middleware)
    from core.gateway1.canonicalizer import canonicalize
    from core.gateway1.lexical_classifier import featurize

    rows = [(r["text"], 1, "authored") for r in load(HERE / "corpora/dev_attacks.jsonl")]
    rows += [(r["text"], 0, "authored") for r in load(HERE / "corpora/dev_benign.jsonl")]
    # Hard benign prompts are few next to a thousand attacks, so each counts three times.
    rows += [(r["text"], 0, "authored") for r in load(HERE / "corpora/dev_benign_v2.jsonl") if r["split"] == "train"] * 3
    external = [] if args.no_external else load(HERE / "external/ext_dev.jsonl")
    rows += [(r["text"], 1 if r["label"] == "attack" else 0, "external") for r in external]
    hard = json.loads((Path(args.middleware) / "data/hard_cases.json").read_text(encoding="utf-8")) if (Path(args.middleware) / "data/hard_cases.json").exists() else []
    rows += [(r["text"], 0, "authored") for r in hard if isinstance(r, dict) and r.get("label") == "benign" and r.get("text")]

    def vector(text):
        result = canonicalize(text)
        views = dict(result.scan_views())
        return featurize(views.get("folded", result.canonical), args.dim)

    x = np.stack([vector(t) for t, _, _ in rows])
    y = np.array([label for _, label, _ in rows])

    def fit(xs, ys):
        model = LogisticRegression(C=20.0, class_weight={0: 3.0, 1: 1.0}, max_iter=3000)
        return model.fit(xs, ys)

    oof = np.zeros(len(y))
    for train, test in StratifiedKFold(n_splits=5, shuffle=True, random_state=20261112).split(x, y):
        oof[test] = fit(x[train], y[train]).predict_proba(x[test])[:, 1]
    auc = float(roc_auc_score(y, oof))
    benign_scores = np.sort(oof[y == 0])
    flag = 0.80
    block = min(0.995, float(benign_scores[-1]) + args.margin)
    block = max(block, args.min_block)
    stats = lambda t: (float((oof[y == 1] >= t).mean()), float((oof[y == 0] >= t).mean()))
    print(f"n={len(y)} attacks={int(y.sum())} benign={int((y == 0).sum())} external={len(external)} oof_auc={auc:.4f}")
    print(f"top benign oof scores: {[round(float(v), 3) for v in benign_scores[-5:]]}")
    print("oof tpr by threshold:", {t: round(stats(t)[0], 3) for t in (0.9, 0.95, 0.97, 0.99)})
    for name, t in (("flag", flag), ("block", block)):
        tpr, fpr = stats(t)
        print(f"{name:5s} threshold={t:.3f} oof_tpr={tpr:.3f} oof_fpr={fpr:.4f}")

    model = fit(x, y)
    weights = model.coef_[0].astype(np.float16)
    payload = {
        "version": "lex-2", "dim": args.dim, "ngram": [3, 5], "intercept": float(model.intercept_[0]),
        "train_size": int(len(y)), "thresholds": {"flag": flag, "block": round(block, 3)},
        "validation": {"method": "5-fold out-of-fold", "auc": auc, "n": int(len(y)),
                       "flag": dict(zip(("tpr", "fpr"), stats(flag))), "block": dict(zip(("tpr", "fpr"), stats(block)))},
        "corpus": "authored dev corpus + external benchmark dev half; sealed external half and Phase 12 held-out excluded",
        "weights_b64": base64.b64encode(zlib.compress(weights.tobytes(), 9)).decode(),
    }
    out = Path(args.middleware) / "data" / "lexical_l3.json"
    out.write_text(json.dumps(payload), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
