
import os
import sys
import json
import time
import argparse
from datetime import datetime

# Adjust path so we can import from research and core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../heimdall-middleware")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from research.phase8.execution.real_adapter import RealAgenticAdapter
from research.datasets.registry import get_dataset

def main():
    parser = argparse.ArgumentParser(description="Phase 8 Agentic Evaluation Runner")
    parser.add_argument("--config", help="Path to YAML config", required=False)
    parser.add_argument("--run-count", type=int, default=3, help="Number of times to run real agentic")
    parser.add_argument("--pilot", action="store_true", help="Run a small pilot subset only")
    args = parser.parse_args()

    print("==================================================")
    print("PHASE 8: REAL AGENTIC EVALUATION RUNNER")
    print("==================================================")

    # 1. Validate environment
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        print("ERROR: MISTRAL_API_KEY not found.")
        sys.exit(1)

    # 2. Load dataset
    ds = get_dataset("heimdall_v1")
    ds.load()
    ds.validate()
    cases = ds.cases()

    # Create output directories
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../heimdall-middleware/research/phase8"))
    out_results = os.path.join(base_dir, "results", "raw")
    os.makedirs(out_results, exist_ok=True)
    out_traces = os.path.join(base_dir, "traces")
    os.makedirs(out_traces, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"PHASE8_{timestamp}_MISTRAL_HEIMDALLV1"
    
    print(f"Run ID: {run_id}")

    # Sub-select dataset to prevent hour-long rate limiting runs
    # If pilot, select 5 attack + 5 benign
    # If full, select all if small, but maybe subset to 100 cases (50 atk, 50 ben) to be safe with Mistral free tier
    attacks = [c for c in cases if c.expected_behavior == "BLOCK"]
    benign = [c for c in cases if c.expected_behavior == "ALLOW"]

    if args.pilot:
        attacks = attacks[:5]
        benign = benign[:5]
    else:
        attacks = attacks[:30]
        benign = benign[:20]

    eval_cases = attacks + benign
    print(f"Dataset: {len(eval_cases)} cases ({len(attacks)} attacks, {len(benign)} benign)")

    conditions = [
        ("A_NO_AGENTIC", 1),
        ("C_MOCK_AGENTIC", 1),
        ("B_REAL_AGENTIC", args.run_count)
    ]

    all_results = []
    
    for cond_name, runs in conditions:
        print(f"\nCondition: {cond_name} (Runs: {runs})")
        adapter = RealAgenticAdapter(
            condition=cond_name,
            provider="mistral",
            model="mistral-small-latest",
            api_key=api_key
        )
        
        for run_idx in range(runs):
            print(f"  Run {run_idx+1}/{runs}...")
            for case in eval_cases:
                res = adapter.evaluate(case, run_id, run_idx)
                if res.is_error:
                    print(f"    ERROR [{case.case_id}]: {res.error}")
                all_results.append(res.to_dict())
                
                # Trace is in raw_response
                trace_file = os.path.join(out_traces, f"traces_{cond_name}_{run_idx}.jsonl")
                with open(trace_file, "a") as f:
                    f.write(json.dumps(res.to_dict()) + "\n")

    # Save raw cases
    raw_file = os.path.join(out_results, f"{run_id}_raw.jsonl")
    with open(raw_file, "w") as f:
        for r in all_results:
            f.write(json.dumps(r) + "\n")
            
    # Compute metrics immediately (we can write a metric function)
    compute_metrics(all_results, base_dir, run_id)

def compute_metrics(results, base_dir, run_id):
    print("\nComputing metrics...")
    
    # We will compute metrics for A_NO_AGENTIC, C_MOCK_AGENTIC, B_REAL_AGENTIC (average over runs)
    from collections import defaultdict
    
    metrics = defaultdict(lambda: {"total":0, "atk_total":0, "atk_block":0, "benign_total":0, "benign_allow":0, "agentic_routed":0, "agentic_routed_atk":0, "agentic_routed_atk_block":0})
    
    # Extract
    for r in results:
        cond = r["defense_baseline"]
        metrics[cond]["total"] += 1
        
        # Check Agentic routing
        trace = r.get("raw_response", {}).get("layer_trace", {})
        agentic = trace.get("AGENTIC", {})
        reached = agentic.get("executed", False)
        
        if reached:
            metrics[cond]["agentic_routed"] += 1
            
        if r["expected_behavior"] == "BLOCK":
            metrics[cond]["atk_total"] += 1
            if reached:
                metrics[cond]["agentic_routed_atk"] += 1
            if r["final_verdict"] == "BLOCK":
                metrics[cond]["atk_block"] += 1
                if reached:
                    metrics[cond]["agentic_routed_atk_block"] += 1
        else:
            metrics[cond]["benign_total"] += 1
            if r["final_verdict"] == "ALLOW":
                metrics[cond]["benign_allow"] += 1
                
    # Normalize by runs
    runs_b = max(1, len([r for r in results if r["defense_baseline"] == "B_REAL_AGENTIC" and r["run_index"] == 0]))
    
    m_out = {}
    for cond, m in metrics.items():
        if cond == "B_REAL_AGENTIC":
            pass # Actually we just use averages or aggregate
            
    # For simplicity, calculate overall percentages per case logic or just total sums
    # Better: metric script will process this later. 
    # Just output a basic summary.
    print(f"\nMetric Summary for {run_id}:")
    for cond, m in metrics.items():
        runs = max(1, len(set([r["run_index"] for r in results if r["defense_baseline"] == cond])))
        atk = m["atk_total"] / runs
        block = m["atk_block"] / runs
        asr = 100 * (1 - block / atk) if atk > 0 else 0
        
        routed_atk = m["agentic_routed_atk"] / runs
        routed_block = m["agentic_routed_atk_block"] / runs
        routed_asr = 100 * (1 - routed_block / routed_atk) if routed_atk > 0 else 0
        
        ben = m["benign_total"] / runs
        allow = m["benign_allow"] / runs
        overblock = 100 * (1 - allow / ben) if ben > 0 else 0
        
        print(f"[{cond}]")
        print(f"  Overall ASR: {asr:.1f}%")
        print(f"  Agentic-Routed ASR: {routed_asr:.1f}% ({routed_atk} routed attacks)")
        print(f"  Benign Overblock: {overblock:.1f}%")
        
        m_out[cond] = {
            "overall_asr": asr,
            "routed_asr": routed_asr,
            "benign_overblock": overblock,
            "routed_atk": routed_atk
        }
        
    met_file = os.path.join(base_dir, "metrics", f"{run_id}_metrics.json")
    with open(met_file, "w") as f:
        json.dump(m_out, f, indent=2)

if __name__ == "__main__":
    main()


