#!/usr/bin/env bash
# Starts all three services for local development. Stop them with Ctrl-C.
set -euo pipefail
cd "$(dirname "$0")"
for service in multi-llm-backend heimdall-middleware; do
  [ -f "$service/.env" ] || { echo "Missing $service/.env. Copy $service/.env.example and fill it in."; exit 1; }
  [ -d "$service/.venv" ] || python3 -m venv "$service/.venv"
  "$service/.venv/bin/pip" install -q -r "$service/requirements.txt"
done
[ -d heimdall-frontend/node_modules ] || (cd heimdall-frontend && npm ci)
trap 'kill 0' EXIT
(cd multi-llm-backend && .venv/bin/uvicorn main:app --port 8001) &
(cd heimdall-middleware && .venv/bin/uvicorn heimdall_app:app --port 8000) &
(cd heimdall-frontend && npm run dev) &
wait
