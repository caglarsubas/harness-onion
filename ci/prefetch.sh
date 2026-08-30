#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "local-cache prefetch accepts no arguments" >&2
  exit 2
fi

for setting in HARNESS_OFFLINE_ENFORCED UV_OFFLINE UV_FROZEN UV_NO_SYNC; do
  if [[ "${!setting:-}" != "1" ]]; then
    echo "local-cache prefetch requires ${setting}=1" >&2
    exit 2
  fi
done

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$repo_root"

# The meta repository has no packet-local materialization step. Prove that the
# preinstalled frozen environment is complete without invoking a resolver.
exec python3 scripts/verify_toolchain.py
