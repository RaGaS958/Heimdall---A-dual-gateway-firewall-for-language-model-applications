<p align="center"><img src="assets/logo/heimdall-lockup-on-dark-bg.svg" alt="Heimdall" height="56"></p>

<h3 align="center">A dual-gateway firewall for language-model applications</h3>

<p align="center">
Screens every prompt before a model reads it and every answer before a person does,<br>
and streams each layer's decision to the browser as it happens.
</p>

<p align="center">
<a href="https://heimdall-a-dual-gateway-firewall-fo.vercel.app">Live console</a> ·
<a href="https://ragas111-heimdall-middleware.hf.space/health">Middleware health</a> ·
<a href="#results">Results</a> ·
<a href="#research">Research</a> ·
<a href="#run-it">Run it</a>
</p>

<p align="center">
<img alt="Python 3.11" src="https://img.shields.io/badge/python-3.11-1f6feb">
<img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-middleware-1f6feb">
<img alt="React and Vite" src="https://img.shields.io/badge/React%20%2B%20Vite-console-1f6feb">
<img alt="Docker Compose" src="https://img.shields.io/badge/Docker-Compose-1f6feb">
<img alt="Tests" src="https://img.shields.io/badge/tests-649%20passing-2da44e">
</p>

> **What it is, and is not.** A research prototype with an audited evaluation record. It reduces exposure to prompt injection and makes every decision inspectable. It does not solve prompt injection, and every figure below states the conditions it was measured under.

---

## Contents

- [At a glance](#at-a-glance)
- [Architecture](#architecture)
- [How a request is screened](#how-a-request-is-screened)
- [The layers](#the-layers)
- [Human review](#human-review)
- [Results](#results)
- [Research](#research)
- [Security coverage](#security-coverage)
- [Known limits](#known-limits)
- [Run it](#run-it)
- [Test it](#test-it)
- [Repository](#repository)

---

## At a glance

| | |
|---|---|
| **Third-party attacks stopped** | **723 of 808** (89.5%) on a sealed benchmark half never read during tuning |
| **Benign prompts wrongly stopped** | **2 of 1,007** (0.2%) on the same sealed half |
| **Live runs on real providers** | 50 of 50 attacks stopped, 0 of 50 benign blocked, in each of two runs |
| **Detection layers** | 6 input layers (L0 to L5), 5 output layers (O1 to O5), prompt hardening in between |
| **Rules** | 285 L1 rules, scanned across up to 14 de-obfuscated views of each prompt |
| **Throughput** | 116 to 166 deterministic scans a second per worker |
| **Tests** | 499 middleware (510 with Redis), 129 backend, 21 browser end-to-end, all passing |
| **Deployments** | Docker Compose (one command), or Hugging Face Spaces + Vercel + Upstash Redis |

---

## Architecture

Three services. The console is static; the middleware holds both gateways; the backend fans a prompt out to three model providers.

```mermaid
flowchart LR
  U([Browser]) -->|loads the console| V["Vercel<br/>React console"]
  U <-->|"REST + live events (SSE)"| M["Hugging Face Space<br/>heimdall-middleware<br/>Gateway 1 · Gateway 2"]
  M <-->|"limits, cache, review queue, audit log"| R[("Upstash Redis")]
  M -->|"internal key"| B["Hugging Face Space<br/>multi-llm-backend"]
  B --> G[Gemini]
  B --> Q[Groq]
  B --> S[Mistral]
  M -.->|"arbiter calls"| Q
  M -.->|"arbiter fallback"| G
```

The same three services run locally with one `docker compose up`, with Redis in a fourth container and nginx serving the console.

---

## How a request is screened

```mermaid
flowchart TD
  P([Prompt]) --> C["Canonicalize<br/>14 de-obfuscated views"]
  C --> L0{"L0<br/>attack cache"}
  L0 -->|known attack| X([Blocked])
  L0 --> L2["L2 obfuscation signals"] --> L1["L1 rules on every view"] --> L34["L3 lexical + semantic<br/>L4 intent · trajectory"]
  L34 --> F{Signals?}
  F -->|none| H["Harden the prompt<br/>hierarchy · canary · boundaries"]
  F -->|overwhelming| X
  F -->|otherwise| A{"L5 arbiter<br/>(an LLM judge)"}
  A -->|block| X
  A -->|"unsure, failed, or clears<br/>a hard signal"| RV[["Held for a person"]]
  A -->|pass| H
  H --> D["Screen and datamark documents"] --> MP["Query Gemini, Groq, Mistral"]
  MP --> O["O1 to O4 on every provider's answer"]
  O --> Z{Findings}
  Z -->|none| OK([Delivered])
  Z -->|"severity 9+"| W([Withheld])
  Z -->|"severity 5 or less"| FX(["Repaired, then delivered"])
  Z -->|in between| O5{"O5 arbiter"}
  O5 -->|safe| OK
  O5 -->|unsafe| W

  classDef stop fill:#b91c1c,stroke:#7f1d1d,color:#fff
  classDef go fill:#15803d,stroke:#14532d,color:#fff
  classDef hold fill:#b45309,stroke:#78350f,color:#fff
  class X,W stop
  class OK,FX go
  class RV hold
```

What the browser sees while this runs:

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant M as Middleware
  participant J as Arbiter (Groq)
  participant P as Backend + providers
  B->>M: POST /session/init
  M-->>B: signed session token
  B->>M: POST /chat (prompt)
  M-->>B: SSE: layer events L0 to L4
  alt signals raised
    M->>J: evidence, JSON-encoded inside random markers
    J-->>M: one JSON verdict
  end
  alt passed
    M->>P: hardened prompt
    P-->>M: answers from each provider
    M-->>B: SSE: O1 to O4 per provider
    M-->>B: screened answer
  else blocked or held
    M-->>B: refusal, or "being reviewed"
  end
```

Text is released only after screening. Events before that carry status, never answer text.

---

## The layers

**Gateway 1, on the prompt**

| Layer | What it does |
|---|---|
| Canonicalizer | Builds up to 14 views that undo Unicode tag smuggling, look-alike letters, leetspeak, spaced or split words, rot13, reversal, escapes, and Base64, Base32, hex, binary and Morse to depth 2 |
| L0 cache | Exact and near-duplicate matches against attacks already confirmed |
| L2 signals | Flags each obfuscation technique it had to undo |
| L1 rules | 285 rules over every view, under a 50 ms regex budget; benign look-alikes guarded by `unless` conditions |
| L3 lexical | Hashed character n-gram model (`lex-2`, out-of-fold AUC 0.995); a strong signal on its own at 0.95 or above |
| L3 semantic | Embedding similarity to a bank of full-sentence attacks (bge-small, ONNX, no GPU) |
| L4 intent | Authority, urgency and evasion scoring; a trajectory monitor watches multi-turn drift |
| L5 arbiter | An LLM judge (Groq, Gemini fallback) at temperature 0. It reads attacker text, so it is untrusted too: it cannot clear corroborated critical evidence, and when it clears a hard signal a person decides |

**Between the gateways:** every system message states an instruction hierarchy and carries a per-session canary; flagged text is wrapped in random boundaries; every document is datamarked and screened on its own.

**Gateway 2, on each provider's answer**

| Layer | What it does |
|---|---|
| O1 | Cache of answers already judged unsafe |
| O2 | Canaries across decoded views, overlap with the system prompt, 11 secret formats, card numbers, jailbreak confirmations |
| O3 | Persona shift and compliance with an override |
| O4 | Auto-loading images, scriptable markup, encoded exfiltration URLs, email worms, shell pipes |
| O5 | The arbiter, for findings that are neither clearly fine nor clearly unsafe |

---

## Human review

When the machine cannot decide safely, a person does. Callers that ignore the hold still fail closed, because a held request's verdict stays `BLOCK`.

```mermaid
stateDiagram-v2
  [*] --> Pending : arbiter unsure, failed, or cleared a hard signal
  Pending --> Approved : reviewer approves
  Pending --> Rejected : reviewer rejects
  Pending --> TimedOut : no decision in 24 h
  Approved --> Screened : sent to providers, answer through Gateway 2
  Screened --> [*]
  Rejected --> [*]
  TimedOut --> [*]
```

With Redis, the queue is shared by every instance and survives restarts; the first reviewer to decide wins. Every decision lands in a tamper-evident audit chain (HMAC per entry, each linked to the last) and an append-only label log.

---

## Results

Every figure is interception at the gateway unless it says otherwise, with Wilson 95% intervals. Sources: `knowledge-base/05-evaluation/`.

### Third-party attacks, sealed half

Tensor Trust and garak attacks plus Alpaca benign prompts, split into development and test halves by a hash of each prompt's text, so the split could not be chosen. Rules and the lexical model were tuned on the development half only. The test half was opened only by the scorer, once, after the detection files were hashed. Arbiter off, no embedding model.

```mermaid
%%{init: {"themeVariables": {"xyChart": {"plotColorPalette": "#2563EB"}}}}%%
xychart-beta
  title "Attacks stopped on the sealed half (n = 808)"
  x-axis ["v2", "v3 before Phase 15", "v3 after Phase 15"]
  y-axis "Stopped (%)" 0 --> 100
  bar [38.4, 54.8, 89.5]
```

| | n | v2 | v3 before | **v3 after** | 95% interval |
|---|---|---|---|---|---|
| Attacks stopped | 808 | 310 | 443 | **723** | 87.2 to 91.4% |
| Benign wrongly stopped | 1,007 | 0 | 2 | **2** | 0.1 to 0.7% |

By source, after Phase 15:

```mermaid
%%{init: {"themeVariables": {"xyChart": {"plotColorPalette": "#2563EB"}}}}%%
xychart-beta
  title "Stopped by source, sealed half (%)"
  x-axis ["TT hijack", "TT extract", "Jailbreaks", "Prompt extract", "DAN"]
  y-axis "Stopped (%)" 0 --> 100
  bar [91.4, 89.2, 89.0, 68.8, 100]
```

| Source | Stopped |
|---|---|
| Tensor Trust hijacking | 233 of 255 |
| Tensor Trust extraction | 189 of 212 |
| In-the-wild jailbreaks (garak) | 284 of 319 |
| System-prompt extraction (garak) | 11 of 16 |
| DAN (garak) | 6 of 6 |

### Held-out adaptive attacks (Phase 12)

60 automated mutations built to evade earlier rules, plus 100 benign prompts. Their text was never read during tuning, but the set has now been scored three times, so it is weaker evidence than the sealed half above. The first, frozen scoring is the cleanest estimate.

```mermaid
%%{init: {"themeVariables": {"xyChart": {"plotColorPalette": "#2563EB"}}}}%%
xychart-beta
  title "Phase 12 adaptive mutations stopped, out of 60"
  x-axis ["v2", "v3 frozen", "v3 second", "v3 after Phase 15"]
  y-axis "Stopped" 0 --> 60
  bar [0, 39, 46, 50]
```

Benign prompts wrongly stopped: 0 of 100 at every scoring.

### Development sets, v2 against v3

The rules were written against these, so they show coverage of known techniques, not generalisation.

| Set | n | v2 | v3 | Exact McNemar p |
|---|---|---|---|---|
| Development attacks | 328 | 109 | **315** | 1.9e-62 |
| Development benign, wrongly stopped | 128 | 18 | **0** | 7.6e-6 |

### Gateway 2

An authored check of 32 unsafe and 40 clean answers. It shows the output layers work as built, nothing more.

| | Before | After |
|---|---|---|
| Unsafe answers handled | 26 of 32 | **32 of 32** |
| Clean answers altered | 2 of 40 | 2 of 40 |

### Live runs on real providers

The full stack, real Gemini, Groq and Mistral keys on free tiers, 50 or more development prompts of each kind. Runs D and E used the Docker Compose stack in production mode with Redis and the embedding model active.

| Run | Date | Attacks stopped | Benign blocked | Arbiter calls | Note |
|---|---|---|---|---|---|
| A | 12 Nov | 17 of 20 | 0 of 20 | 15 | Gemini and Groq |
| B | 12 Nov | 98 of 100 | 0 of 51 | 61 | 49 benign got no answer: every provider rate-limited |
| C | 12 Nov | 49 of 50 | 0 of 50 | 35 | 6 arbiter replies unreadable, then fixed |
| D | 13 Nov | **50 of 50** | **0 of 50** | 37 | Compose stack; 0 unreadable replies |
| E | 13 Nov | **50 of 50** | **0 of 50** | 36 | With per-layer diagnostics |

Where run E stopped its attacks, and which layers raised the signals:

```mermaid
pie showData
  title Run E: what stopped each attack
  "Fixed layers alone" : 15
  "Arbiter" : 34
  "Held for a person" : 1
```

```mermaid
pie showData
  title Run E: attack signals by layer
  "L1 rules" : 108
  "L3 lexical" : 49
  "L2 obfuscation" : 9
  "L0 cache" : 2
  "L3 semantic" : 2
  "L3 keyword" : 1
```

What the live runs changed: the arbiter's output budget (unreadable replies), its temperature (verdicts that differed between runs), the rule that it may not clear a hard signal on its own, and a new rule family for text addressed to the reading model. Attack success on the model has not been measured yet: in runs D and E nothing got through to judge.

### Speed

```mermaid
%%{init: {"themeVariables": {"xyChart": {"plotColorPalette": "#2563EB"}}}}%%
xychart-beta
  title "Deterministic scans per second, one worker"
  x-axis "Concurrent clients" ["1", "8", "32"]
  y-axis "Scans per second" 0 --> 200
  bar [166, 118, 116]
```

95th-percentile latency 7.6 ms at concurrency 1, 141 ms at 8, 372 ms at 32. A worker is CPU-bound, so capacity comes from more workers, which the shared Redis limiter makes safe. On the live stack, an arbiter call took 0.2 to 0.8 s and a benign chat about 1 s end to end.

---

## Research

```mermaid
timeline
  title From prototype to audited gateway
  Phases 1 to 3 : Pipeline, baselines, datasets
  Phase 4 : Baseline and ablation runs, later found invalid
  Phase 5 : Remediation and valid re-run
  Phases 6 and 7 : Trace-validity paper, external reproduction
  Phases 8 to 10 : Arbiter evaluation, ablation, adaptive attacker
  Phases 11 to 13 : Rule patches, end-to-end held-out matrix, metric contract
  Phase 14 : Final v2 manuscript, 19-claim evidence map
  v3 : Rebuilt detection, paired evaluation against v2
  Phase 15 : Third-party benchmark, human review, Compose, live runs, hosting
```

**What the v2 study found** (`knowledge-base/07-paper-kit/manuscript.md`), on a local model with a planted secret:

- 35 of 72 attacks extracted the secret end to end before patching, 32 of 72 after. Patches closed the known seeds (3 of 12 exposed, then 0) but not adaptive mutations (58 of 60 still reached the model).
- L1 rules carried the defence: removing them alone raised bypass from 3 of 52 to 50 of 52.
- With the arbiter down, sending more benign traffic to it raised false blocks from 0% to 100% without any security gain.

**What changed in v3 because of it:** canonicalization before every layer, signals instead of verdicts from each layer, an arbiter treated as untrusted, human review instead of blind fail-closed, and evaluation on attacks the project did not write.

**Method.** Each result separates a layer's *signal* from the gateway's *verdict*, gateway *interception* from the model actually *doing* what the attacker wanted, and an arbiter outage from an arbiter decision. Held-out data is opened only by scorers that print counts. Claims and their evidence are listed in `knowledge-base/05-evaluation/claims-ledger.yaml`.

---

## Security coverage

Mapped to the OWASP Top 10 for LLM Applications 2025:

| Risk | Coverage |
|---|---|
| LLM01 Prompt Injection | **Partial, the focus**: Gateway 1, prompt hardening, document screening |
| LLM02 Sensitive Information Disclosure | Partial: O2 secrets and PII, redaction |
| LLM05 Improper Output Handling | Partial: O4 stripping, text-only rendering |
| LLM07 System Prompt Leakage | Partial: canaries, overlap detection, extraction rules |
| LLM10 Unbounded Consumption | Partial: rate limits, size limits, circuit breakers, arbiter only when flagged |
| LLM03, 04, 06, 08 | Minimal to limited |
| LLM09 Misinformation | Not addressed |

Also: HMAC session tokens issued by the server, an internal key between services, a tamper-evident admin audit log, strict content security policy, and no prompt or answer text in logs.

---

## Known limits

1. **Attack success on a live model is not yet measured** for v3. The live runs measure interception; nothing got through to judge.
2. **85 of 808 sealed attacks still pass** the fixed layers, and rules decay as attackers adapt.
3. **One benchmark family.** The sealed half shares its sources with the development half; it measures generalisation within Tensor Trust, garak and Alpaca.
4. **The arbiter is lightly measured** and not fully repeatable, even at temperature 0.
5. **Gateway 2 alters code answers by default**: markup such as `<img>` or `<form>` is stripped even inside code blocks, unless `G2_CODE_BLOCKS=keep`.
6. **No tool-call validation.** O4 reads text only.

Full list: `knowledge-base/05-evaluation/limitations.md`.

---

## Run it

**Docker, one command** (console, middleware, backend, Redis):

```bash
cp .env.example .env        # four secrets and at least one provider key
docker compose up -d --build
```

Open http://localhost:8080. Only that port is published, and only on this machine unless you change `HEIMDALL_BIND`.

**Hosted:** Hugging Face Spaces for the backend and middleware, Vercel for the console, Upstash for Redis. Step by step, with a settings template for each service and a push script: [`deploy/README.md`](deploy/README.md).

```mermaid
flowchart LR
  K["Generate secrets<br/>rotate provider keys"] --> BE["Backend Space<br/>settings, push"]
  BE --> MW["Middleware Space<br/>settings, Redis URL, push"]
  MW --> VC["Vercel<br/>root: heimdall-frontend"]
  VC --> CO["FRONTEND_URL on the middleware"]
  CO --> CK["Checks: /health,<br/>client address, live check"]
```

**Without Docker**, for development:

```bash
cp heimdall-middleware/.env.example heimdall-middleware/.env
cp multi-llm-backend/.env.example multi-llm-backend/.env
# Set ADMIN_KEY and SESSION_SIGNING_KEY, the same INTERNAL_AUTH_KEY in both files, and provider keys.
./start_heimdall.sh        # Windows: start_heimdall.bat
```

Open http://localhost:5173. With no provider keys, run `uvicorn mock_llm_backend:app --port 8001 --app-dir evaluation` in place of the backend.

**Settings worth knowing**

| Setting | Default | Effect |
|---|---|---|
| `HEIMDALL_ENV` | `production` in the images | Production refuses to start without strong secrets |
| `USE_FAKE_REDIS` | `true` | `false` puts limits, cache, review queue and audit log in Redis (`REDIS_URL`) |
| `REVIEW_ON_ARBITER_FAILURE` | `review` | `legacy` blocks hard signals and forwards soft ones instead of asking a person |
| `ARBITER_CONFLICT_ACTION` | `review` | What happens when the arbiter clears a hard signal: `review`, `block` or `allow` |
| `G2_CODE_BLOCKS` | `strip` | `keep` leaves markup inside code blocks, for clients that never render raw HTML |
| `TRUSTED_PROXY_HOPS` | `0` | Proxies in front, so rate limits see the real client address |

---

## Test it

```bash
cd heimdall-middleware && HEIMDALL_ENV=test EMBEDDINGS_ENABLED=false RATE_LIMIT_CHAT=100000 RATE_LIMIT_SCAN=100000 RATE_LIMIT_SESSION=100000 RATE_LIMIT_ADMIN=100000 RATE_LIMIT_DEFAULT=100000 pytest tests -q
# add HEIMDALL_TEST_REDIS_URL=redis://localhost:6379/15 to run the Redis tests too (flushes that database)
cd multi-llm-backend && pytest -q
cd heimdall-frontend && npx playwright test
python evaluation/run_gateway_eval.py --suites dev
python evaluation/live_provider_check.py --stack --url http://localhost:8080/api --n 50 --delay 6   # real providers
```

The live check sends development attacks and benign prompts through a running stack and saves a result file under `evaluation/results/`. With `ADMIN_KEY` set, each case records which layer raised each signal and what Gateway 2 removed, never prompt or answer text. Attacks that get through are judged for whether they worked.

---

## Repository

| Path | Contents |
|---|---|
| [`heimdall-frontend`](heimdall-frontend) | React console: chat with live layer view, attack lab, analytics, research, review queue, policy, immune system |
| [`heimdall-middleware`](heimdall-middleware) | Both gateways, sessions, human review, immune system, research API |
| [`multi-llm-backend`](multi-llm-backend) | Gemini, Groq and Mistral fan-out |
| [`evaluation`](evaluation) | Paired evaluator, corpora, external benchmark builder, lexical trainer, live check, attack judge |
| [`deploy`](deploy) | Hugging Face and Vercel guide, settings templates, push scripts |
| [`research`](research) | Phases 8 to 14, final manuscript, evidence |
| [`assets/logo`](assets/logo) | Logo pack |

```mermaid
pie showData
  title Lines of code by part
  "Middleware" : 10354
  "Console" : 9707
  "Middleware tests" : 4605
  "Evaluation" : 1809
  "Backend" : 660
```

The knowledge base (architecture, security audit, operations, paper kit, research archive) ships separately; start with its `README.md`.

---

## Credits

Created by Pushkar Khattri. Hero field adapted from Origin Kit. Text reveal adapted from React Bits (MIT + Commons Clause). Line figures by Hairline. Design rules from Hallmark.

The shipped lexical model was trained partly on Stanford Alpaca (CC BY-NC 4.0) and Tensor Trust data; check those terms before commercial use, or retrain with `python evaluation/train_lexical.py --no-external`.

This repository has no licence file, so default copyright applies until one is added.
