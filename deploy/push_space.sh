#!/usr/bin/env bash
# Push one Heimdall service to its Hugging Face Space (macOS/Linux; see push_space.ps1 for Windows).
#   deploy/push_space.sh backend    RaGaS111/multi-llm-backend
#   deploy/push_space.sh middleware RaGaS111/heimdall-middleware
set -euo pipefail
service="${1:?middleware or backend}"; space="${2:?owner/space-name}"
root="$(cd "$(dirname "$0")/.." && pwd)"
case "$service" in
  middleware) src="$root/heimdall-middleware" ;;
  backend)    src="$root/multi-llm-backend" ;;
  *) echo "service must be middleware or backend" >&2; exit 2 ;;
esac
work="$(mktemp -d)/space"
git clone "https://huggingface.co/spaces/$space" "$work"
find "$work" -mindepth 1 -maxdepth 1 ! -name .git ! -name .gitattributes -exec rm -rf {} +

tar -C "$src" \
  --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache --exclude=node_modules --exclude=tests \
  --exclude='research/figures' --exclude='research/paper' --exclude='research/analysis' \
  --exclude='research/artifact*' --exclude='research/phase*' --exclude='research/results/raw' \
  --exclude='research/results/normalized' --exclude='research/exports' \
  --exclude=.env --exclude=.env.local --exclude='*.pyc' --exclude='*.db' --exclude='review_queue.json*' \
  --exclude='admin_audit.jsonl*' --exclude=honeypot_logs.jsonl --exclude=reviewer_labels.jsonl \
  --exclude=extdev_misses.json -cf - . | tar -C "$work" -xf -

# *.db is left out: Hugging Face refuses plain-git binary files (see push_space.ps1).
if grep -rIlE 'gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}' --exclude-dir=.git "$work"; then
  echo "Key-like text found above. Refusing to push." >&2; exit 1
fi

cd "$work"
git add -A
if git diff --cached --quiet; then echo "Space is already up to date."; exit 0; fi
git commit -q -m "Deploy $service"
git push
echo "Pushed. The Space rebuilds now: https://huggingface.co/spaces/$space"
