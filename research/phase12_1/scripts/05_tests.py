import subprocess
import json
import os
import sys

def main():
    print("Running Phase 12.1 Regression & Integrity Tests")
    
    # 1. New Phase 12.1 tests
    res_integrity = subprocess.run(["pytest", "research/phase12_1/tests/"], capture_output=True, text=True)
    print("Phase 12.1 Integrity Tests:\n", res_integrity.stdout)
    
    # 2. Historical Regressions
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    # Ensure it runs from heimdall-middleware so relative paths in tests work
    res_regr = subprocess.run(["pytest", "../harness/test_audit_regressions.py"], cwd="heimdall-middleware", env=env, capture_output=True, text=True)
    print("Historical Regressions:\n", res_regr.stdout)
    
    regression_results = {
        "integrity_status": "PASSED" if res_integrity.returncode == 0 else "FAILED",
        "integrity_output": res_integrity.stdout,
        "historical_status": "PASSED" if res_regr.returncode == 0 else "FAILED",
        "historical_output": res_regr.stdout,
    }
    
    with open("research/phase12_1/results/regression_results.json", "w") as f:
        json.dump(regression_results, f, indent=2)
        
    print("Tests completed.")
    if res_integrity.returncode != 0 or res_regr.returncode != 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
