#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# The sandbox images only pull public base images.  Ignore the host's Docker
# credential helper by default so a stale Docker Desktop/WSL login session
# cannot prevent these builds.  An explicitly supplied DOCKER_CONFIG is still
# respected for users who intentionally need custom Docker configuration.
if [[ -z "${DOCKER_CONFIG:-}" ]]; then
  BUILD_DOCKER_CONFIG="$(mktemp -d "${TMPDIR:-/tmp}/ctf-os-docker-config.XXXXXX")"
  trap 'rm -rf -- "$BUILD_DOCKER_CONFIG"' EXIT
  printf '%s\n' '{"auths":{}}' > "$BUILD_DOCKER_CONFIG/config.json"
  export DOCKER_CONFIG="$BUILD_DOCKER_CONFIG"
  echo "Using an isolated Docker configuration for public image pulls."
fi

for profile in base pwn web rev crypto forensic; do
  docker build \
    --build-arg "CTF_OS_PROFILE=${profile}" \
    --file "$ROOT/sandbox/Dockerfile.sandbox" \
    --tag "ctf-os-sandbox:${profile}" \
    "$ROOT"
done
