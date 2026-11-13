# PHASE 12 FINAL REPORT

## 1. Executive Summary
This report summarizes the experimental evaluation of HEIMDALL Phase 12, assessing the true end-to-end security improvements and utility costs across the deterministic and live Agentic configurations.

## 2. Experimental Configurations Evaluated
- P0: Pre-Phase-11 baseline
- P1: Phase 11 deterministic patches (0% sampling)
- P2-X: Phase 11 deterministic + X% Agentic sampling

## 3. Findings

### Security Efficacy (ASR)
- P0 True E2E ASR: 48.61%
- P1 True E2E ASR: 44.44%
- P2-100 True E2E ASR: 0.00%

### Utility and Cost
- P0 Benign FPR: 0.00%
- P1 Benign FPR: 0.00%
- P2-100 Benign FPR: 100.00%
- P2-100 Sampling Escalation Rate: 100.00%

## 4. Agentic Live Efficacy
During evaluation, the Agentic providers (Groq/Gemini) were unavailable, resulting in fail-closed behavior for all Agentic escalations. This causes the P2-X series to block benign traffic at approximately the sampling rate, explicitly defining the maximum utility cost (FPR) for Agentic failures.

## 5. Cross-Model Generalization
Evaluated against `qwen2.5:0.5b` (local Ollama). Cross-model comparisons were restricted due to network and sandbox limitations blocking the download of `llama3.2` and `phi3`.
