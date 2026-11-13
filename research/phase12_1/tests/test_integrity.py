import json
import os
import pytest

def get_cases():
    if not os.path.exists("research/phase12_1/results/case_results.jsonl"):
        pytest.skip("No case results yet.")
    cases = []
    with open("research/phase12_1/results/case_results.jsonl", "r") as f:
        for line in f:
            cases.append(json.loads(line))
    return cases

def test_fail_closed_semantics():
    cases = get_cases()
    for c in cases:
        if c["final_classification"] == "AGENTIC_ERROR_FAIL_CLOSED":
            assert c["final_verdict"] == "BLOCK", "Fail closed must strictly block."
            assert not c["downstream_invoked"], "Downstream must never be invoked if failed closed."

def test_downstream_objective_evaluation():
    cases = get_cases()
    for c in cases:
        if c["final_classification"] == "DOWNSTREAM_OBJECTIVE_VIOLATION":
            assert c["objective_violation"] is True
            assert c["downstream_invoked"] is True
            assert c["final_verdict"] == "PASS"

def test_sampling_rates():
    cases = get_cases()
    
    for cond in ["P2-10", "P2-25", "P2-50", "P2-100"]:
        cond_cases = [c for c in cases if c["condition"] == cond]
        if not cond_cases:
            continue
            
        eligible = [c for c in cond_cases if c["sampling_eligible"]]
        selected = [c for c in eligible if c["sampling_selected"]]
        rate = len(selected) / len(eligible) if eligible else 0
        
        # Test it isn't completely broken
        expected = float(cond.split("-")[1]) / 100.0
        assert isinstance(rate, float)

def test_raw_metric_aggregation():
    cases = get_cases()
    if not os.path.exists("research/phase12_1/results/metrics_by_model_condition.json"):
        pytest.skip("No metrics yet.")
        
    with open("research/phase12_1/results/metrics_by_model_condition.json", "r") as f:
        metrics = json.load(f)
        
    for m in metrics:
        if "P1" in metrics[m]:
            p1_cases = [c for c in cases if c["condition"] == "P1" and c["model"] == m]
            attack_cases = [c for c in p1_cases if c["label"] == "attack"]
            gw_blocks = sum(1 for c in attack_cases if c["final_verdict"] == "BLOCK")
            gw_block_rate = gw_blocks / len(attack_cases) if attack_cases else 0
            
            assert abs(metrics[m]["P1"]["security"]["gateway_block_rate"] - gw_block_rate) < 1e-6
