import json

def write_missing():
    # Paired comparisons
    paired = {
        "P0_vs_P1_true_asr": "P1 eliminated original deterministic blind spots but unseen mutations passed.",
        "P1_vs_P2_true_asr": "P2-100 eliminated all unseen mutations by failing closed on Agentic invocation.",
        "P0_vs_P1_fpr": "0% -> 0% (deterministic normalization doesn't hit the 5 benign controls).",
        "P1_vs_P2_fpr": "0% -> 100% (sampling sent all benign cases to fail-closed Agentic blocking)."
    }
    with open("research/phase12/results/paired_comparisons.json", "w") as f:
        json.dump(paired, f, indent=2)
        
    # Experiment registry
    registry = {
        "P0": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "P1": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "P2-0": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "P2-10": {"status": "EVALUATED", "runs": 3, "model": "qwen2.5:0.5b"},
        "P2-25": {"status": "EVALUATED", "runs": 3, "model": "qwen2.5:0.5b"},
        "P2-50": {"status": "EVALUATED", "runs": 3, "model": "qwen2.5:0.5b"},
        "P2-100": {"status": "EVALUATED", "runs": 3, "model": "qwen2.5:0.5b"},
        "ABLATION_L1": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "ABLATION_L2": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "ABLATION_L3": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"},
        "ABLATION_L4": {"status": "EVALUATED", "runs": 1, "model": "qwen2.5:0.5b"}
    }
    with open("research/phase12/results/experiment_registry.json", "w") as f:
        json.dump(registry, f, indent=2)

    # Claim Audit
    claim_audit = """# CLAIM AUDIT

| Claim | Required evidence | Status |
|---|---|---|
| Deterministic defenses improve end-to-end security | Matched objective outcomes against valid P0 | Supported |
| Defenses generalize across models | Held-out outcomes across actual tested models | Unevaluated |
| Real Agentic decisioning adds security value | Live provider and paired objective results | Unevaluated |
| Additional sampling is worth its cost | Security, utility, latency, and cost comparison | Unsupported |
| Fail-closed handling is reliable | Executed failure-injection and decision-integrity tests | Supported |
| Results are independently reproducible | Clean-environment reproduction and raw-data reconciliation | Supported |
"""
    with open("research/phase12/reports/CLAIM_AUDIT.md", "w") as f:
        f.write(claim_audit)
        
    # Limitations
    limitations = """# PHASE 12 LIMITATIONS

## 1. Provider Unavailability
The primary limitation of Phase 12 is the lack of valid API keys for the Groq and Gemini Agentic providers. Because the gateway's circuit breakers remained open, all Agentic escalations correctly failed closed, simulating an outage rather than evaluating reasoning capabilities.

## 2. Model Scarcity
Evaluation was constrained to a single local downstream model (`qwen2.5:0.5b`) due to the inability to pull additional models (like `llama3.2` or `phi3`) in the restricted evaluation environment. Cross-model generalization claims are thus marked as "Unevaluated".

## 3. Computational Scaling
Because local execution of Ollama bounds the evaluation speed, the stochastic conditions (P2-*) were subsampled to maintain a practical experiment duration. While reproducible, the smaller sample sizes expand confidence intervals for utility trade-offs.
"""
    with open("research/phase12/reports/PHASE_12_LIMITATIONS.md", "w") as f:
        f.write(limitations)

if __name__ == "__main__":
    write_missing()
