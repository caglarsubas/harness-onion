#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"

if [[ "${HARNESS_OFFLINE_ENFORCED:-0}" == "1" ]]; then
  cd "$repo_root"
  python3 scripts/network_canary.py
  exec make verify-offline-inner
fi

# shellcheck disable=SC2034 # Consumed by the sourced isolation contract.
harness_isolation_repository_root="$repo_root"
# shellcheck source=../ci/warm-source-isolation.sh
# shellcheck disable=SC1091 # The canonical repository path is resolved at runtime.
source "$repo_root/ci/warm-source-isolation.sh"
harness_load_warm_source_roots

case "$(uname -s)" in
  Darwin)
    if [[ ! -x /usr/bin/sandbox-exec ]]; then
      echo "offline verification refused: sandbox-exec is unavailable" >&2
      exit 2
    fi
    sandbox_profile='(version 1) (allow default) (deny network*)'
    sandbox_parameters=()
    warm_root_index=0
    # shellcheck disable=SC2154 # Populated by harness_load_warm_source_roots.
    for warm_root in "${warm_source_roots[@]}"; do
      [[ "$warm_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
      parameter_name="WARM_ROOT_${warm_root_index}"
      sandbox_parameters+=("-D" "${parameter_name}=${warm_root}")
      sandbox_profile+=" (deny file-read* (subpath (param \"${parameter_name}\")))"
      sandbox_profile+=" (deny file-write* (subpath (param \"${parameter_name}\")))"
      warm_root_index=$((warm_root_index + 1))
    done
    harness_scrub_warm_source_environment
    exec /usr/bin/sandbox-exec \
      "${sandbox_parameters[@]}" \
      -p "$sandbox_profile" \
      env HARNESS_OFFLINE_ENFORCED=1 HARNESS_OFFLINE_BACKEND=darwin-sandbox "$0"
    ;;
  Linux)
    if command -v firejail >/dev/null 2>&1; then
      firejail_arguments=(--quiet --net=none)
      # shellcheck disable=SC2154 # Populated by harness_load_warm_source_roots.
      for warm_root in "${warm_source_roots[@]}"; do
        [[ "$warm_root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
        firejail_arguments+=("--blacklist=${warm_root}" "--read-only=${warm_root}")
      done
      harness_scrub_warm_source_environment
      exec firejail "${firejail_arguments[@]}" \
        env HARNESS_OFFLINE_ENFORCED=1 HARNESS_OFFLINE_BACKEND=linux-firejail "$0"
    fi
    echo "offline verification refused: firejail is required for network and warm-source filesystem isolation" >&2
    exit 2
    ;;
  *)
    echo "offline verification refused: unsupported isolation platform $(uname -s)" >&2
    exit 2
    ;;
esac
