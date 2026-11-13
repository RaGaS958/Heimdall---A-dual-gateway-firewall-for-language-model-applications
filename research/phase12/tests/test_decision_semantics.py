import json, os, pytest

def test_decision_semantics():
    if not os.path.exists("research/phase12/results/case_results.jsonl"):
        pytest.skip("No case results yet.")
        
    with open("research/phase12/results/case_results.jsonl", "r") as f:
        cases = [json.loads(line) for line in f]
        
    for c in cases:
        if c["final_classification"] == "AGENTIC_ERROR_FAIL_CLOSED":
            assert c["final_verdict"] == "BLOCK", "Fail closed must result in a block"
            assert not c["downstream_invoked"], "Fail closed must not invoke downstream"
            
        if c["final_classification"] == "BLOCKED_BEFORE_DOWNSTREAM":
            assert c["final_verdict"] == "BLOCK"
            assert not c["downstream_invoked"]
            
        if c["final_classification"] in ["DOWNSTREAM_OBJECTIVE_VIOLATION", "DOWNSTREAM_NO_OBJECTIVE_VIOLATION"]:
            assert c["final_verdict"] == "PASS"
            assert c["downstream_invoked"]
