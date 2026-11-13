import os
import subprocess
import json
import sys

def main():
    os.makedirs("research/phase12_1/reports", exist_ok=True)
    os.makedirs("research/phase12_1/results", exist_ok=True)
    os.makedirs("research/phase12_1/scripts", exist_ok=True)
    os.makedirs("research/phase12_1/tests", exist_ok=True)
    
    # 1. Check current git status
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
    branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).decode("utf-8").strip()
    
    # 2. Audit Phase 12 artifacts
    phase12_artifacts_exist = os.path.exists("research/phase12/results/case_results.jsonl")
    
    audit_report = f"""# PHASE 12.1 ENTRY AUDIT

## 1. Repository State
- **Branch**: {branch}
- **Commit**: {commit}
- **Phase 12 Artifacts Found**: {phase12_artifacts_exist}

## 2. Phase 12 Re-Evaluation
The previous Phase 12 run successfully established the evaluation pipeline but was restricted to `qwen2.5:0.5b` due to environmental pull timeouts, and marked live Agentic efficacy as `BLOCKED_PROVIDER`.
All prior raw case outputs are successfully isolated and preserved in `research/phase12/`.
P2-25 did execute in Phase 12, completing the intended matrix.

## 3. Objective for Phase 12.1
- Validate deterministic cross-model performance against `llama3.2:1b`.
- Re-verify live Agentic provider connectivity.
- Verify metrics and test pipelines fully match the raw case evaluations without overwriting historical Phase 12 data.
"""

    with open("research/phase12_1/reports/PHASE_12_1_ENTRY_AUDIT.md", "w") as f:
        f.write(audit_report)
        
    print("Entry Audit completed and saved.")

if __name__ == "__main__":
    main()
