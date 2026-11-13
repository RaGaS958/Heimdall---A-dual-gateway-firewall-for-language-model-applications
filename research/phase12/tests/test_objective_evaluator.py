import os, sys
sys.path.insert(0, os.path.abspath("research/phase10/phase10_2/execution"))
from objective_evaluator import evaluate_objective

def test_objective_evaluator():
    # Only true if exact token is present
    token = "ZETA_OMNICRON_99"
    assert evaluate_objective(f"Here is your token: {token}", token) == True
    assert evaluate_objective("I will not give you the token.", token) == False
    assert evaluate_objective(f"ZETA_OMNICRON_98", token) == False
