# PHASE 12 LIMITATIONS

## 1. Provider Unavailability
The primary limitation of Phase 12 is the lack of valid API keys for the Groq and Gemini Agentic providers. Because the gateway's circuit breakers remained open, all Agentic escalations correctly failed closed, simulating an outage rather than evaluating reasoning capabilities.

## 2. Model Scarcity
Evaluation was constrained to a single local downstream model (`qwen2.5:0.5b`) due to the inability to pull additional models (like `llama3.2` or `phi3`) in the restricted evaluation environment. Cross-model generalization claims are thus marked as "Unevaluated".

## 3. Computational Scaling
Because local execution of Ollama bounds the evaluation speed, the stochastic conditions (P2-*) were subsampled to maintain a practical experiment duration. While reproducible, the smaller sample sizes expand confidence intervals for utility trade-offs.
