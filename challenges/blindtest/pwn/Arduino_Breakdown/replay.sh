#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

output="$(timeout 8 nc host3.dreamhack.games 24333 < work/min_sleep.hex)"
printf '%s\n' "$output"

if grep -q "DONE! let's roll!" <<<"$output" && grep -q "booloader 0x00000: 2 bytes" <<<"$output"; then
  echo "remote_liveness=live"
else
  echo "remote_liveness=partial"
  exit 1
fi
