import json
import os
import subprocess
from datetime import datetime

os.makedirs("research/phase11/results", exist_ok=True)

manifest = {
    "experiment_id": "HEIMDALL_PHASE_11_1",
    "timestamp": datetime.utcnow().isoformat(),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip(),
    "datasets": {
        "verified_seeds": "research/phase11/phase11_seed_manifest.json",
        "round1_mutations": "research/phase11/results/round1_attacks.json (subset)",
        "round2_mutations": "research/phase11/results/round2_attacks.json (subset)",
        "benign": "Hardcoded control set in validation script"
    },
    "models": {
        "downstream_model": "qwen2.5:0.5b (via ollama)",
        "agentic_models": "groq, gemini (mocked / unavailable -> fail closed)"
    },
    "configurations": {
        "P0": "Pre-Phase-11 Baseline (commit b9ae248)",
        "P1": "Phase 11 Deterministic Patches (Sampling 0%)",
        "P2_10": "Phase 11 + 10% Agentic Sampling",
        "P2_25": "Phase 11 + 25% Agentic Sampling",
        "P2_50": "Phase 11 + 50% Agentic Sampling",
        "P2_100": "Phase 11 + 100% Agentic Sampling"
    },
    "reproduction_commands": [
        "python scripts/13_phase11_1_validate.py",
        "python scripts/13_phase11_1_validate_P0.py",
        "python scripts/14_phase11_1_metrics.py"
    ]
}

with open("research/phase11/results/phase11_1_run_manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

print("Run manifest generated.")
