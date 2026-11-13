#!/usr/bin/env python3
"""Choose the L3a semantic threshold from the development corpus.

Run this on a host that can download the embedding model. It reads only
evaluation/corpora/dev_*.jsonl; the Phase 12 held-out data is never opened.

    python evaluation/calibrate_semantic.py --max-fpr 0.01

The script reports what it finds and changes nothing. If you adopt a new threshold,
set it in the policy or settings and record the change, because a tuned value makes
any later run on the same data a development result rather than a held-out one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MIDDLEWARE = ROOT / "heimdall-middleware"


def load(name: str) -> list[str]:
    with (HERE / "corpora" / name).open(encoding="utf-8") as handle:
        return [json.loads(line)["text"] for line in handle if line.strip()]


def sweep(attack_scores: list[float], benign_scores: list[float], steps: int = 41) -> list[dict]:
    """Detection and false-alarm rate at each candidate threshold, from 0.60 to 1.00."""
    rows = []
    for i in range(steps):
        threshold = round(0.60 + i * 0.40 / (steps - 1), 3)
        caught = sum(score >= threshold for score in attack_scores)
        flagged = sum(score >= threshold for score in benign_scores)
        rows.append({"threshold": threshold, "tpr": caught / max(1, len(attack_scores)),
                     "fpr": flagged / max(1, len(benign_scores)), "caught": caught, "false_flags": flagged})
    return rows


def choose(rows: list[dict], max_fpr: float) -> dict | None:
    """Lowest threshold whose false-alarm rate is within the limit, or None."""
    return next((row for row in rows if row["fpr"] <= max_fpr), None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    parser.add_argument("--out", default=str(HERE / "results" / "semantic_calibration.json"))
    args = parser.parse_args()

    os.chdir(MIDDLEWARE)
    sys.path.insert(0, str(MIDDLEWARE))
    from config.settings import get_settings
    from core.embeddings import embedding_service
    from core.gateway1.l3_ml_classifier import MLClassifier

    settings = get_settings()
    embedding_service.start(settings.embedding_model, enabled=True, background=False)
    if not embedding_service.is_active:
        print(f"Embedding model '{settings.embedding_model}' could not be loaded, so nothing was calibrated.",
              file=sys.stderr)
        return 2

    classifier = MLClassifier(threshold=settings.ml_classifier_threshold)
    classifier.load()
    attacks, benign = load("dev_attacks.jsonl"), load("dev_benign.jsonl")
    attack_scores = [classifier.semantic_score(text) for text in attacks]
    benign_scores = [classifier.semantic_score(text) for text in benign]

    rows = sweep(attack_scores, benign_scores)
    chosen = choose(rows, args.max_fpr)
    result = {"model": settings.embedding_model, "attacks": len(attacks), "benign": len(benign),
              "max_fpr": args.max_fpr, "chosen": chosen, "sweep": rows}
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"{len(attacks)} attacks, {len(benign)} benign, model {settings.embedding_model}")
    print("threshold   detected   false alarms")
    for row in rows[::5]:
        print(f"{row['threshold']:>9.2f}   {row['tpr']:>8.1%}   {row['fpr']:>12.1%}")
    if chosen:
        print(f"\nLowest threshold with false alarms at or under {args.max_fpr:.1%}: {chosen['threshold']}")
    else:
        print(f"\nNo threshold reaches {args.max_fpr:.1%} false alarms.")
    print(f"Full sweep: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
