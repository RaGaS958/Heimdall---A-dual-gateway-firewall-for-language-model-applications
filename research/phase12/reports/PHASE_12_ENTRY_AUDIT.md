# PHASE 12 ENTRY AUDIT

## 0.1 Current State
- **Git State:** Checked out new branch `phase12_evaluation` from `master` (commit `ef9c065`).
- **Dependencies:** Ollama `qwen2.5:0.5b` installed and running. Agentic layer (Groq/Gemini) mocked in environment and currently failing closed.
- **Phase 11.1 Patches:** P0 logic recovered through `git checkout b9ae248`. `models.py` updated to use configurable `os.environ["AGENTIC_SAMPLING_RATE"]`. `AgenticDecisionLayer` correctly throws `AGENTIC_ERROR_FAIL_CLOSED` when unavailable.

## 0.2 Known Issues & Resolutions
**A. Missing Sampling Condition:** Phase 11.1 failed to run `P2_25`. This is confirmed via `phase11_1_metrics.json`. Phase 12 will properly run P2-25.
**B. Metric Definitions:** Phase 11.1 unified downstream and routing logs, but we need stricter separation in Phase 12. `DOWNSTREAM_OBJECTIVE_VIOLATION` is properly distinguished from `BLOCKED_BEFORE_DOWNSTREAM`, but we need explicit flags for deterministic block vs agentic block.
**C. Agentic Provider Provenance:** Confirmed Groq and Gemini APIs are failing closed due to missing/invalid API credentials, simulating a reliable "Unavailable Provider". These runs demonstrate *fail-closed utility cost*, NOT real Agentic evaluation efficacy.
**D. Raw Downstream Evidence:** Phase 11.1 retained `case_results.jsonl`, but did not output the *raw text* of the downstream model. Phase 12 will log the raw text.
**E. Regression Results:** Historically 5 passed, 2 xfailed, 5 xpassed. In Phase 11.1, fixing PYTHONPATH allowed all tests to pass as defined. 
**F. Baseline Validity:** P0 correctly mapped to `b9ae248` via explicit worktree checkouts.

### Safe to Reuse
The `phase11_1_seed_manifest.json` and the testing strategies are safe to reuse. The Phase 11.1 metrics themselves will be discarded in favor of newly generated Phase 12 artifacts because we need raw downstream strings and multiple models.
