#!/usr/bin/env bash
# Boot the hot-omelet dev environment. Idempotent: safe to run every session.
set -euo pipefail
cd "$(dirname "$0")"

echo "== python =="
pip install -e . || pip install .

echo "== external tools (optional, needs sudo/go) =="
echo "skip: run 'hot install' manually when a tool is missing"

echo "== rust tools =="
for t in hot_beam_rs hot_bf_rs; do
  if [ -d "tools/rust/$t" ]; then
    (cd "tools/rust/$t" && cargo build --release) || echo "warn: $t build failed"
  fi
done

echo "== smoke =="
hot --help >/dev/null && echo "hot CLI ok"
echo "done. Next: cat README.md"
