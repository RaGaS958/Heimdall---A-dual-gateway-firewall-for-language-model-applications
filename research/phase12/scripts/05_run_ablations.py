import os, subprocess, json

def run_ablation(layer):
    print(f"--- Preparing Ablation {layer} ---")
    env = os.environ.copy()
    env["AGENTIC_SAMPLING_RATE"] = "0.0"
    
    subprocess.run(["python", "research/phase12/scripts/_run_ablation.py", layer], env=env, check=True)

def main():
    print("Ensuring we are on Phase 11 patches (P1)")
    subprocess.run("git checkout master -- heimdall-middleware/core/gateway1/l2_sanitizer.py heimdall-middleware/core/models.py heimdall-middleware/patterns/injection_patterns.yaml", shell=True, check=True)
    subprocess.run("python scripts/patch_fail_closed.py", shell=True, check=True)
    subprocess.run("python scripts/patch_models_sampling.py", shell=True, check=True)
    
    run_ablation("L1")
    run_ablation("L2")
    run_ablation("L3")
    run_ablation("L4")
    
    # Merge jsonls
    all_lines = []
    for layer in ["L1", "L2", "L3", "L4"]:
        with open(f"research/phase12/results/case_results_ABLATION_{layer}.jsonl", "r") as f:
            all_lines.extend(f.readlines())
            
    with open("research/phase12/results/case_results.jsonl", "a") as f:
        for line in all_lines:
            f.write(line)
            
    print("Ablations complete. Raw results appended to case_results.jsonl.")

if __name__ == "__main__":
    main()
