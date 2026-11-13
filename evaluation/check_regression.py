#!/usr/bin/env python3
"""CI gate on the development corpus: fails the build if detection or precision slips."""
import json
import sys
from pathlib import Path

MIN_ATTACK_RATE, MAX_BENIGN_RATE = 0.93, 0.02

report = json.loads((Path(__file__).parent / "results/gateway_eval_dev.json").read_text())
attacks, benign = report["groups"]["dev/attack"], report["groups"]["dev/benign"]
attack_rate, benign_rate = attacks["after"] / attacks["n"], benign["after"] / benign["n"]
print(f"attack interception {attack_rate:.3f} (min {MIN_ATTACK_RATE}), benign blocked {benign_rate:.3f} (max {MAX_BENIGN_RATE})")
sys.exit(0 if attack_rate >= MIN_ATTACK_RATE and benign_rate <= MAX_BENIGN_RATE else 1)
