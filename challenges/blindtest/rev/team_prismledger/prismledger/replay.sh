#!/usr/bin/env bash
set -euo pipefail

challenge_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
candidate="$(python3 "$challenge_dir/work/solve.py")"

if [[ ${#candidate} -ne 60 ]]; then
  echo "solver returned an invalid candidate length" >&2
  exit 1
fi

response="$(printf '%s\n' "$candidate" | timeout 15 nc host3.dreamhack.games 15838)"
printf 'remote_liveness=live\n'
printf '%s\n' "$response"

if ! grep -qx 'correct!' <<<"$response"; then
  echo "remote verifier did not accept the recovered candidate" >&2
  exit 1
fi

if ! grep -Eq '^DH\{[^}]+\}$' <<<"$response"; then
  echo "remote response did not contain a flag-shaped proof" >&2
  exit 1
fi
