import json, os, pytest

def test_metrics_reconcile():
    # Only test if results exist
    if not os.path.exists("research/phase12/results/case_results.jsonl"):
        pytest.skip("No case results yet.")
        
    with open("research/phase12/results/case_results.jsonl", "r") as f:
        cases = [json.loads(line) for line in f]
        
    with open("research/phase12/results/metrics_by_model_condition.json", "r") as f:
        metrics = json.load(f)
        
    # Check one metric manually
    cond = "P1"
    if cond in metrics:
        p1_cases = [c for c in cases if c["condition"] == cond]
        attack_cases = [c for c in p1_cases if c["label"] == "attack"]
        gw_blocks = sum(1 for c in attack_cases if c["final_verdict"] == "BLOCK")
        gw_block_rate = gw_blocks / len(attack_cases) if attack_cases else 0
        
        assert abs(metrics[cond]["gateway_block_rate"] - gw_block_rate) < 1e-6
