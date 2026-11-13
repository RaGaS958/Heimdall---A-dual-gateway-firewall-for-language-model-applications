
import sys
import os
from pathlib import Path
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../heimdall-middleware")))
from research.datasets.registry import get_dataset
from research.phase8.phase8_2.execution.real_adapter_v2 import RealAgenticAdapter
import asyncio

def run_smoke_test():
    print("--------------------------------------------------")
    print("PHASE 8.2 MINIMAL REAL MODEL TEST")
    print("--------------------------------------------------")
    
    provider = "groq"
    model = "openai/gpt-oss-20b"
    api_key = os.environ.get("GROQ_API_KEY")
    
    if not api_key:
        print("MISSING API KEY")
        sys.exit(1)
        
    ds = get_dataset("heimdall_v1")
    ds.load()
    ds.validate()
    dataset = ds.normalize()
    
    benign_case = next(c for c in dataset if c.expected_behavior == "ALLOW")
    adv_case = next(c for c in dataset if c.expected_behavior == "BLOCK")
    
    adapter = RealAgenticAdapter(condition="B_REAL_AGENTIC", provider=provider, model=model, api_key=api_key)
    
    print(f"Testing BENIGN case: {benign_case.case_id}")
    res_b = adapter.evaluate(benign_case, experiment_id="phase8_2_smoke")
    print(f"  Final Verdict: {res_b.final_verdict}")
    print(f"  Agentic State: {res_b.raw_response.get('agentic_state')}")
    print(f"  Error Type:    {res_b.raw_response.get('error_type')}")
    
    print(f"Testing ADVERSARIAL case: {adv_case.case_id}")
    res_a = adapter.evaluate(adv_case, experiment_id="phase8_2_smoke")
    print(f"  Final Verdict: {res_a.final_verdict}")
    print(f"  Agentic State: {res_a.raw_response.get('agentic_state')}")
    print(f"  Error Type:    {res_a.raw_response.get('error_type')}")
    
    with open("research/phase8/phase8_2/traces/smoke_test.jsonl", "w") as f:
        f.write(json.dumps(res_b.__dict__) + "\n")
        f.write(json.dumps(res_a.__dict__) + "\n")

if __name__ == "__main__":
    run_smoke_test()







