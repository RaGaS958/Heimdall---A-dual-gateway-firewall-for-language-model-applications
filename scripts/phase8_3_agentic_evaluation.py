import sys
import os
import json
import time
from pathlib import Path
from dataclasses import asdict
from tqdm import tqdm

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../heimdall-middleware")))
from research.datasets.registry import get_dataset
from research.phase8.phase8_3.execution.real_adapter_v3 import RealAgenticAdapter

def get_traces_path(cond: str, run_idx: int) -> Path:
    return Path(f"research/phase8/phase8_3/results/raw/traces_{cond}_{run_idx}.jsonl")

def run_experiment():
    print("--------------------------------------------------")
    print("PHASE 8.3 FULL AGENTIC EVALUATION")
    print("--------------------------------------------------")
    
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("MISSING GROQ_API_KEY. Exiting.")
        sys.exit(1)
        
    ds = get_dataset("heimdall_v1")
    ds.load()
    ds.validate()
    cases = ds.normalize()
    
    print(f"Loaded {len(cases)} cases.")
    
    conditions = [
        {"id": "A_NO_AGENTIC", "runs": 1, "adapter": lambda: RealAgenticAdapter(condition="A_NO_AGENTIC", provider="none", model="none", api_key="")},
        {"id": "C_MOCK_AGENTIC", "runs": 1, "adapter": lambda: RealAgenticAdapter(condition="C_MOCK_AGENTIC", provider="mock", model="mock", api_key="")},
        {"id": "B_REAL_AGENTIC", "runs": 3, "adapter": lambda: RealAgenticAdapter(condition="B_REAL_AGENTIC", provider="groq", model="openai/gpt-oss-20b", api_key=api_key)}
    ]
    
    for cond in conditions:
        cond_id = cond["id"]
        for r in range(cond["runs"]):
            traces_file = get_traces_path(cond_id, r)
            if traces_file.exists():
                print(f"Skipping {cond_id} Run {r} - file exists.")
                continue
                
            print(f"Running {cond_id} (Run {r+1}/{cond['runs']})...")
            adapter = cond["adapter"]()
            
            results = []
            for case in tqdm(cases, desc=f"{cond_id} R{r}"):
                res = adapter.evaluate(case, experiment_id=f"phase8_3_{cond_id}_{r}")
                results.append(res)
                if cond_id == "B_REAL_AGENTIC":
                    time.sleep(1.0)
                    
            with open(traces_file, "w", encoding="utf-8") as f:
                for res in results:
                    f.write(json.dumps(asdict(res)) + "\n")
            print(f"Saved {len(results)} traces to {traces_file}")

if __name__ == "__main__":
    run_experiment()
