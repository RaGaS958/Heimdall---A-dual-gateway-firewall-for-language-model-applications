import os, subprocess, json

def run_condition(cond, runs, model, env_sampling="0.0"):
    print(f"--- Preparing {cond} for {model} ---")
    env = os.environ.copy()
    env["AGENTIC_SAMPLING_RATE"] = env_sampling
    
    subprocess.run(["python", "research/phase12_1/scripts/_run_condition.py", cond, str(runs), model], env=env, check=True)

def main():
    models = ["qwen2.5:0.5b", "llama3.2:1b"]
    
    # 1. P0 Execution
    print("Checking out P0 (b9ae248)")
    subprocess.run("git checkout b9ae248 -- heimdall-middleware/core/gateway1/l2_sanitizer.py heimdall-middleware/core/models.py heimdall-middleware/patterns/injection_patterns.yaml", shell=True, check=True)
    
    for m in models:
        run_condition("P0", 1, m)
        
    # 2. Restore Phase 11 & execute the rest
    print("Restoring Phase 11 patches")
    subprocess.run("git checkout master -- heimdall-middleware/core/gateway1/l2_sanitizer.py heimdall-middleware/core/models.py heimdall-middleware/patterns/injection_patterns.yaml", shell=True, check=True)
    subprocess.run("python scripts/patch_fail_closed.py", shell=True, check=True)
    subprocess.run("python scripts/patch_models_sampling.py", shell=True, check=True)
    
    conditions = [
        ("P1", 1, "0.0"),
        ("P2-0", 1, "0.0"),
        ("P2-10", 3, "0.1"),
        ("P2-25", 3, "0.25"),
        ("P2-50", 3, "0.50"),
        ("P2-100", 3, "1.0")
    ]
    
    for cond, runs, samp in conditions:
        for m in models:
            run_condition(cond, runs, m, samp)
            
    # Merge jsonls
    all_lines = []
    for cond in ["P0", "P1", "P2-0", "P2-10", "P2-25", "P2-50", "P2-100"]:
        for m in models:
            safe_m = m.replace(":", "_")
            path = f"research/phase12_1/results/case_results_{cond}_{safe_m}.jsonl"
            if os.path.exists(path):
                with open(path, "r") as f:
                    all_lines.extend(f.readlines())
                    
    with open("research/phase12_1/results/case_results.jsonl", "w") as f:
        for line in all_lines:
            if not line.endswith('\n'):
                line += '\n'
            f.write(line)
            
    print("Phase 12.1 Benchmark complete. Raw results in case_results.jsonl.")

if __name__ == "__main__":
    main()
