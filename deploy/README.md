# Deploying to Hugging Face Spaces and Vercel

| Service | Where | Folder |
|---|---|---|
| Model backend | Space `RaGaS111/multi-llm-backend` | `multi-llm-backend` |
| Middleware (both gateways) | Space `RaGaS111/heimdall-middleware` | `heimdall-middleware` |
| Site | Vercel | `heimdall-frontend` |

Both Spaces build from the `Dockerfile` in their folder and listen on 7860, as the README headers declare. A Space's address is `https://<owner>-<space-name>.hf.space`, lower case, with dots and underscores turned into dashes. Yours: `https://ragas111-multi-llm-backend.hf.space` and `https://ragas111-heimdall-middleware.hf.space`.

## 1. Secrets

Generate three random values (`python -c "import secrets;print(secrets.token_urlsafe(48))"`): `ADMIN_KEY`, `INTERNAL_AUTH_KEY` and `SESSION_SIGNING_KEY`. Use fresh provider keys. Keys that have ever been pasted into a chat, a file or a log should be revoked first.

Enter everything in **Settings > Variables and secrets** of each Space. Anything secret goes under *New secret*. *Variables* are public on a public Space.

## 2. Backend Space

1. Enter the values in `hf-backend.env.example`. `INTERNAL_AUTH_KEY` is required: without it the backend answers every request with 403, and in production it refuses to start.
2. Push the code: `.\deploy\push_space.ps1 -Service backend -Space RaGaS111/multi-llm-backend` (macOS/Linux: `deploy/push_space.sh backend RaGaS111/multi-llm-backend`). Git asks for your Hugging Face username and a **write** token.
3. When the Space shows *Running*, open `https://ragas111-multi-llm-backend.hf.space/health`. All three providers should show as configured.

Keep this Space public. A private Space needs a Hugging Face token on every request, which the middleware does not send. The shared key protects `/query`, and `/health` reveals no key.

## 3. Middleware Space

1. The Space exists already; check it is a Docker Space on CPU basic.
2. Recommended: create a free Redis database on Upstash (upstash.com) in the region nearest the Space and copy its `rediss://` URL. It goes in the secret `REDIS_URL`, with the variable `USE_FAKE_REDIS=false`. Redis then holds the rate limits, session locks, attack cache, review queue, reviewer labels and audit log, so they survive restarts and rebuilds. Without Redis, all of that resets whenever the Space restarts, unless you mount a Storage Bucket at `/data` and set the four `/data/...` paths instead.
3. Enter the values in `hf-middleware.env.example`. Set `FRONTEND_URL` once you know the Vercel address (step 4); changing it only restarts the Space.
4. Push the code: `.\deploy\push_space.ps1 -Service middleware -Space RaGaS111/heimdall-middleware`.
5. Open `https://ragas111-heimdall-middleware.hf.space/health`. Expect `multi_llm_backend: ok`, `agentic: ok`, and with Redis `rate_limiter: redis` and `state_storage: redis`. `rate_limiter: memory` with `USE_FAKE_REDIS=false` means the Space could not reach Redis: check `REDIS_URL` (it must start with `rediss://`) and the Space logs. Without Redis, `state_storage: ok` means the files are writable; `not_writable` means the bucket is mounted read-only or at another path. The first start downloads the 130 MB embedding model, so give it a minute.

## 4. Vercel

1. Import the repository, set **Root Directory** to `heimdall-frontend`. Vercel detects Vite (`npm run build`, output `dist`).
2. Add `VITE_HEIMDALL_URL` from `vercel.env.example` and deploy. `vercel.json` already allows `https://*.hf.space` in the content security policy.
3. Put the Vercel address in the middleware's `FRONTEND_URL`. Preview deployments have other addresses and will be refused by CORS unless you add them.

## 5. Checks after deploying

**Client address.** Rate limits are per client address, so the middleware must read it correctly through Hugging Face's proxy:

```powershell
$m = "https://ragas111-heimdall-middleware.hf.space"
try { Invoke-WebRequest "$m/review/queue" -Headers @{ "X-Admin-Key" = "wrong" } | Out-Null } catch { }
(Invoke-RestMethod "$m/audit/log?limit=1" -Headers @{ "X-Admin-Key" = "<ADMIN_KEY>" }).entries | Select-Object ip, action
```

The `ip` of the refused attempt should be your own public address. A Hugging Face or private address means `TRUSTED_PROXY_HOPS` is wrong: try 2, restart, check again. With 0, every visitor shares one rate limit.

**Live check.** From the repository root, with `ADMIN_KEY` set in the environment:

```powershell
python evaluation/live_provider_check.py --stack --url https://ragas111-heimdall-middleware.hf.space --n 50 --delay 6
```

## What is different from Docker Compose

- **Redis is hosted elsewhere.** Upstash's free tier allows 500,000 commands a month. A chat uses a handful, so a demo stays well inside it. Without Redis (`USE_FAKE_REDIS=true`), limits, locks, cache and the review queue live in the process and in files and reset on restart.
- **Instances.** With Redis, more than one middleware instance can share the review queue and audit chain. Without it, keep one.
- **Sleep.** A free CPU basic Space sleeps after 48 hours without requests; the next visitor waits for it to start and load the embedding model.
- **Databases are not pushed.** Hugging Face refuses binary files over plain git. The immune database is rebuilt at start; the Research page's experiment registry stays empty on the Space.
