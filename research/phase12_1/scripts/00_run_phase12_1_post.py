import os
import subprocess
import sys

def main():
    print("=== HEIMDALL PHASE 12.1 POST-EVALUATION ===")
    
    scripts = [
        "research/phase12_1/scripts/04_metrics.py",
        "research/phase12_1/scripts/05_tests.py",
        "research/phase12_1/scripts/06_reports.py"
    ]
    
    for script in scripts:
        print(f"\n--- Running {script} ---")
        res = subprocess.run(["python", script])
        if res.returncode != 0:
            print(f"FAILED: {script}")
            sys.exit(1)
            
    print("\nPhase 12.1 post-evaluation completed successfully.")
    
    print("\nCommitting Phase 12.1 artifacts...")
    subprocess.run("git add research/phase12_1/ ; git commit -m \"Phase 12.1: Cross-model E2E completion\"", shell=True)

if __name__ == "__main__":
    main()
