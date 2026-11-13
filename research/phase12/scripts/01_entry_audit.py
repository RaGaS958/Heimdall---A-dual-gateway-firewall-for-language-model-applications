import os, subprocess, sys

def audit():
    print("Running Phase 12 Entry Audit...")
    
    # Check Ollama
    try:
        import requests
        models = requests.get("http://localhost:11434/api/tags").json()
        print(f"Ollama running. Found models: {[m['name'] for m in models.get('models', [])]}")
    except Exception as e:
        print("Warning: Ollama not running or reachable.", e)
        
    # Check Phase 11 artifacts
    if not os.path.exists("research/phase11/results/phase11_1_metrics.json"):
        print("Warning: Phase 11.1 metrics not found.")
    else:
        import json
        with open("research/phase11/results/phase11_1_metrics.json", "r") as f:
            metrics = json.load(f)
            if "P2_25" not in metrics:
                print("Confirmed missing P2_25 in Phase 11.1 metrics. Phase 12 will include it.")
                
    # Run tests
    print("Running audit regressions...")
    env = os.environ.copy()
    env["PYTHONPATH"] = "heimdall-middleware"
    res = subprocess.run(["pytest", "harness/test_audit_regressions.py"], env=env, capture_output=True, text=True)
    if res.returncode == 0:
        print("All audit regressions passed.")
    else:
        print("Audit regressions failed or had XPASS/XFAIL. See output:")
        print(res.stdout)
        
if __name__ == "__main__":
    audit()
