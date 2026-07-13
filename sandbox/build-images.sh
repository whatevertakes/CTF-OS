#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
for profile in base pwn web rev crypto forensic; do
  docker build \
    --build-arg "CTF_OS_PROFILE=${profile}" \
    --file "$ROOT/sandbox/Dockerfile.sandbox" \
    --tag "ctf-os-sandbox:${profile}" \
    "$ROOT"
done
