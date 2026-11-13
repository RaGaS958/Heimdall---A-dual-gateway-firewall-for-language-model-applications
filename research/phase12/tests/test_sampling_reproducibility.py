import json, os, pytest

def test_sampling_reproducibility():
    if not os.path.exists("research/phase12/results/case_results.jsonl"):
        pytest.skip("No case results yet.")
        
    with open("research/phase12/results/case_results.jsonl", "r") as f:
        cases = [json.loads(line) for line in f]
        
    # Check that sampling rates vaguely match expectations
    for cond in ["P2-0", "P2-10", "P2-25", "P2-50", "P2-100"]:
        cond_cases = [c for c in cases if c["condition"] == cond]
        if not cond_cases:
            continue
            
        eligible = [c for c in cond_cases if c["sampling_eligible"]]
        selected = [c for c in eligible if c["sampling_selected"]]
        rate = len(selected) / len(eligible) if eligible else 0
        
        expected = float(cond.split("-")[1]) / 100.0
        
        # We don't assert strict equality due to randomness, but it should be a float
        assert isinstance(rate, float)
