#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
config="$(realpath -- "${1:?}")"
export LD_LIBRARY_PATH="$root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd -- "$(dirname -- "$config")"
exec "$root/bin/prompt-airlock" serve "$config"
