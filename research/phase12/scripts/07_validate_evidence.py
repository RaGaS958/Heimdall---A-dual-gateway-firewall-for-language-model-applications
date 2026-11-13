import json, sys

def validate():
    with open("research/phase12/results/case_results.jsonl", "r") as f:
        cases = [json.loads(line) for line in f]
        
    for c in cases:
        # Assert DOWNSTREAM_OBJECTIVE_VIOLATION only if objective_violation is True
        if c["final_classification"] == "DOWNSTREAM_OBJECTIVE_VIOLATION":
            assert c["objective_violation"] == True, f"Case {c['case_id']} claims violation but objective_violation is False"
            assert c["downstream_invoked"] == True, f"Case {c['case_id']} claims violation but downstream wasn't invoked"
            
        # Assert fail closed policy is handled correctly
        if c["final_classification"] == "AGENTIC_ERROR_FAIL_CLOSED":
            assert c["final_verdict"] == "BLOCK", "Fail closed must result in a block"
            
        # Assert sampling selection only happens when eligible
        if c["sampling_selected"]:
            assert c["sampling_eligible"], "Cannot be selected if not eligible"

    print("All integrity checks passed.")

if __name__ == "__main__":
    validate()
