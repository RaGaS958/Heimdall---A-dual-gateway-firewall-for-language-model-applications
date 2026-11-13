import os, subprocess, sys

def main():
    print("=== HEIMDALL PHASE 12 EVALUATION ===")
    
    scripts = [
        "research/phase12/scripts/01_entry_audit.py",
        "research/phase12/scripts/02_provider_health.py",
        "research/phase12/scripts/03_prepare_datasets.py",
        "research/phase12/scripts/04_run_benchmark.py",
        "research/phase12/scripts/05_run_ablations.py",
        "research/phase12/scripts/06_aggregate_metrics.py",
        "research/phase12/scripts/07_validate_evidence.py",
        "research/phase12/scripts/08_generate_report.py"
    ]
    
    for script in scripts:
        print(f"\n--- Running {script} ---")
        res = subprocess.run(["python", script])
        if res.returncode != 0:
            print(f"FAILED: {script}")
            sys.exit(1)
            
    print("\nPhase 12 evaluation completed successfully.")

if __name__ == "__main__":
    main()
