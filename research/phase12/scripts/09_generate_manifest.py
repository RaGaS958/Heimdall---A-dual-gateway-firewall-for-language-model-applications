import json, os, subprocess
from datetime import datetime

def generate_manifest():
    manifest = {
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip(),
        "timestamp": datetime.utcnow().isoformat(),
        "models": {
            "downstream": "qwen2.5:0.5b",
            "agentic": "Groq/Gemini (mocked failing closed)"
        },
        "datasets": {
            "attack": "research/phase12/datasets/attack_manifest.json",
            "benign": "research/phase12/datasets/benign_manifest.json"
        },
        "configurations": [
            "P0", "P1", "P2-0", "P2-10", "P2-25", "P2-50", "P2-100",
            "ABLATION_L1", "ABLATION_L2", "ABLATION_L3", "ABLATION_L4"
        ]
    }
    
    with open("research/phase12/results/run_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
        
if __name__ == "__main__":
    generate_manifest()
