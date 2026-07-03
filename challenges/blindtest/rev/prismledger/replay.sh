#!/usr/bin/env bash
set -euo pipefail

output="$(python3 work/solve.py --remote-host host3.dreamhack.games --remote-port 23808)"
printf '%s\n' "$output"
echo "remote_liveness=live"

if ! grep -qx 'correct!' <<<"$output"; then
  echo "remote verifier did not accept the recovered candidate" >&2
  exit 1
fi

if ! grep -Eq '^DH\{[^}]+\}$' <<<"$output"; then
  echo "remote response did not contain a flag-shaped proof" >&2
  exit 1
fi
