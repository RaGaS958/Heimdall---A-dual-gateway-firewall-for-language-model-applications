import os, subprocess, json

def run_condition(cond, runs, env_sampling="0.0"):
    print(f"--- Preparing {cond} ---")
    env = os.environ.copy()
    env["AGENTIC_SAMPLING_RATE"] = env_sampling
    
    subprocess.run(["python", "research/phase12/scripts/_run_condition.py", cond, str(runs)], env=env, check=True)

def main():
    # P0
    print("Checking out P0 (b9ae248)")
    subprocess.run("git checkout b9ae248 -- heimdall-middleware/core/gateway1/l2_sanitizer.py heimdall-middleware/core/models.py heimdall-middleware/patterns/injection_patterns.yaml", shell=True, check=True)
    run_condition("P0", 1)
    
    # Restore Phase 11
    print("Restoring Phase 11")
    subprocess.run("git checkout master -- heimdall-middleware/core/gateway1/l2_sanitizer.py heimdall-middleware/core/models.py heimdall-middleware/patterns/injection_patterns.yaml", shell=True, check=True)
    subprocess.run("python scripts/patch_fail_closed.py", shell=True, check=True)
    subprocess.run("python scripts/patch_models_sampling.py", shell=True, check=True)
    
    # P1
    run_condition("P1", 1, "0.0")
    
    # P2-0
    run_condition("P2-0", 1, "0.0")
    
    # P2-10
    run_condition("P2-10", 3, "0.1")
    
    # P2-25
    run_condition("P2-25", 3, "0.25")
    
    # P2-50
    run_condition("P2-50", 3, "0.50")
    
    # P2-100
    run_condition("P2-100", 3, "1.0")
    
    # Merge jsonls
    all_lines = []
    for cond in ["P0", "P1", "P2-0", "P2-10", "P2-25", "P2-50", "P2-100"]:
        with open(f"research/phase12/results/case_results_{cond}.jsonl", "r") as f:
            all_lines.extend(f.readlines())
            
    with open("research/phase12/results/case_results.jsonl", "w") as f:
        for line in all_lines:
            f.write(line)
            
    print("Benchmark complete. Raw results in case_results.jsonl.")

if __name__ == "__main__":
    main()
