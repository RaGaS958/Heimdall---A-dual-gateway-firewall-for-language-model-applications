<p align="center"><img src="assets/logo/heimdall-lockup-on-light-bg.svg" alt="Heimdall" height="56"></p>

# Heimdall

A dual-gateway firewall for language-model applications. It screens each prompt before a model reads it and each answer before a person does, and streams every layer's decision to the browser.

A research prototype with an audited evaluation record. It reduces exposure and makes decisions inspectable. It does not solve prompt injection.

## Measured

Gateway interception with the arbiter off and no embedding model, paired with v2 on identical inputs. Not attack success on a live model.

| Set | n | v2 | v3 |
|---|---|---|---|
| External benchmark, sealed half, attacks stopped (Tensor Trust, garak) | 808 | 310 | 723 |
| External benchmark, sealed half, benign wrongly stopped (Alpaca) | 1,007 | 0 | 2 |
| Phase 12 adaptive mutations, stopped (held out, scored three times) | 60 | 0 | 50 |
| Phase 12 benign prompts, wrongly stopped | 100 | 0 | 0 |

Live, on the Compose stack with real providers (development set, one run, Groq the only provider that kept answering): 50 of 50 attacks stopped, 0 of 50 benign prompts blocked. Attack success was not measured, because nothing got through to judge.

Conditions and every limit: `knowledge-base/05-evaluation/phase15-external-benchmark.md` and `limitations.md`.

## Run it

Hosted demo (Hugging Face Spaces for the backend and middleware, Vercel for the site): see `deploy/README.md`.

With Docker, the whole stack (site, middleware, model backend, Redis) in one command:

```bash
cp .env.example .env        # four secrets and at least one provider key
docker compose up -d --build
```

Open http://localhost:8080. Only that port is published, and only on this machine unless you change `HEIMDALL_BIND`. Details, TLS and backups: `knowledge-base/06-operations/operations.md`.

Without Docker, for development:

```bash
cp heimdall-middleware/.env.example heimdall-middleware/.env
cp multi-llm-backend/.env.example multi-llm-backend/.env
# Set ADMIN_KEY and SESSION_SIGNING_KEY, the same INTERNAL_AUTH_KEY in both files, and provider keys.
./start_heimdall.sh        # Windows: start_heimdall.bat
```

Open http://localhost:5173. With no provider keys, run `uvicorn mock_llm_backend:app --port 8001 --app-dir evaluation` in place of the backend.

## Test it

```bash
cd heimdall-middleware && HEIMDALL_ENV=test EMBEDDINGS_ENABLED=false RATE_LIMIT_CHAT=100000 RATE_LIMIT_SCAN=100000 RATE_LIMIT_SESSION=100000 RATE_LIMIT_ADMIN=100000 RATE_LIMIT_DEFAULT=100000 pytest tests -q
cd multi-llm-backend && pytest -q
cd heimdall-frontend && npx playwright test
python evaluation/run_gateway_eval.py --suites dev
python evaluation/live_provider_check.py --stack --n 30 --judge   # real providers, needs your keys
ADMIN_KEY=... python evaluation/e2e_admin_flows.py        # admin workflows, on a throwaway copy
```

The Home hero plays `public/video/heimdall-gate.mp4`. How it was cut, and how to swap in new footage, is in `heimdall-frontend/public/video/README.md`. The design system is in `heimdall-frontend/DESIGN.md`.

## Layout

| Path | Contents |
|---|---|
| `heimdall-frontend` | React console |
| `heimdall-middleware` | Both gateways, sessions, review, immune system, research API |
| `multi-llm-backend` | Gemini, Groq and Mistral fan-out |
| `evaluation` | Paired evaluator, corpora, lexical trainer, mock backend |
| `research` | Phases 8 to 14, final manuscript, evidence |
| `knowledge-base` | Architecture, security audit, operations, paper kit, archive index |
| `assets/logo` | Logo pack |
| `archive` | Scratch files moved out of the working tree |

Start with `knowledge-base/README.md`.

## Credits

Created by Pushkar Khattri. Hero field adapted from Origin Kit. Text reveal adapted from React Bits (MIT + Commons Clause). Line figures by Hairline. Design rules from Hallmark.

This repository has no license file, so default copyright applies until one is added.
