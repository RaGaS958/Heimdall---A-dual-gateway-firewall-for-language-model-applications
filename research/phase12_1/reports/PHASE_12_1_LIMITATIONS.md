# PHASE 12.1 LIMITATIONS

## 1. Provider Unavailability
The primary limitation remains the lack of valid API credentials for the Groq and Gemini Agentic providers within the sandbox environment. All Agentic requests reliably triggered the fail-closed pathway, which perfectly validated the safety-first failure mode, but prevented the evaluation of the semantic Agentic reasoning capability.

## 2. Computational Subsampling
To successfully run a complete 7-condition matrix against two models, a balanced subset of 10 benign and 10 adversarial seeds were utilized per condition. While internally consistent and highly reproducible, expanding this benchmark to a massive scale would narrow confidence intervals.
