#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_ROOT="$ROOT/sandbox/requirements-lock"
EXCLUDE_NEWER="2026-07-25T00:00:00Z"
PLATFORM="x86_64-manylinux_2_36"

command -v uv >/dev/null || {
  echo "uv is required to regenerate Python dependency locks." >&2
  exit 69
}
mkdir -p "$LOCK_ROOT/isolated"

compile_lock() {
  local output="$1"
  shift
  local sources=()
  local source
  for source in "$@"; do
    sources+=("$ROOT/$source")
  done
  uv pip compile \
    "${sources[@]}" \
    --python-version 3.11 \
    --python-platform "$PLATFORM" \
    --exclude-newer "$EXCLUDE_NEWER" \
    --generate-hashes \
    --no-annotate \
    --custom-compile-command sandbox/lock-python-requirements.sh \
    --output-file "$ROOT/$output" \
    >/dev/null
}

compile_torch_lock() {
  local backend="$1" output="$2"
  shift 2
  local sources=()
  local source
  for source in "$@"; do
    sources+=("$ROOT/$source")
  done
  # PyTorch's package indexes do not expose upload timestamps, so uv cannot
  # apply --exclude-newer to these resolutions. The generated hashes remain
  # the immutable build input.
  uv pip compile \
    "${sources[@]}" \
    --python-version 3.11 \
    --python-platform "$PLATFORM" \
    --torch-backend "$backend" \
    --generate-hashes \
    --no-annotate \
    --custom-compile-command sandbox/lock-python-requirements.sh \
    --output-file "$ROOT/$output" \
    >/dev/null
}

COMMON=sandbox/requirements.txt
BINARY=sandbox/requirements/binary-analysis.txt
AI=sandbox/requirements/ai.txt
MISC=sandbox/requirements/misc.txt
CRYPTO=sandbox/requirements/crypto.txt

# Every layered lock describes the complete Python environment at that build
# step. This prevents a later profile install from silently replacing a
# version pinned by the common or parent profile layer.
compile_lock sandbox/requirements-lock/common.txt "$COMMON"
compile_lock sandbox/requirements-lock/binary-analysis.txt \
  "$COMMON" "$BINARY"
compile_lock sandbox/requirements-lock/pwn.txt \
  "$COMMON" "$BINARY" sandbox/requirements/pwn.txt
compile_lock sandbox/requirements-lock/pwn-fuzzing.txt \
  "$COMMON" "$BINARY" sandbox/requirements/pwn.txt \
  sandbox/requirements/pwn-fuzzing.txt
compile_lock sandbox/requirements-lock/web.txt \
  "$COMMON" sandbox/requirements/web.txt
compile_lock sandbox/requirements-lock/rev.txt \
  "$COMMON" "$BINARY" sandbox/requirements/rev.txt
compile_lock sandbox/requirements-lock/crypto.txt \
  "$COMMON" "$CRYPTO"
compile_lock sandbox/requirements-lock/cuda-nvrtc.txt \
  "$COMMON" "$CRYPTO" sandbox/requirements/cuda-nvrtc.txt
compile_lock sandbox/requirements-lock/forensic.txt \
  "$COMMON" sandbox/requirements/forensic.txt
compile_lock sandbox/requirements-lock/misc.txt \
  "$COMMON" "$MISC"
compile_lock sandbox/requirements-lock/osint.txt \
  "$COMMON" sandbox/requirements/osint.txt
compile_lock sandbox/requirements-lock/ai.txt \
  "$COMMON" "$AI"
compile_torch_lock cu126 sandbox/requirements-lock/torch-cu126.txt \
  "$COMMON" "$AI" sandbox/requirements/torch-cu126.txt
compile_torch_lock cu126 sandbox/requirements-lock/ai-security.txt \
  "$COMMON" "$AI" sandbox/requirements/torch-cu126.txt \
  sandbox/requirements/ai-security.txt
compile_torch_lock cpu sandbox/requirements-lock/torch-cpu.txt \
  "$COMMON" "$MISC" sandbox/requirements/torch-cpu.txt
compile_lock sandbox/requirements-lock/cloud.txt \
  "$COMMON" sandbox/requirements/cloud.txt

for tool in checkov holehe jwt-tool maigret mitmproxy rsactftool semgrep sherlock theharvester; do
  compile_lock \
    "sandbox/requirements-lock/isolated/${tool}.txt" \
    "sandbox/requirements/isolated/${tool}.txt"
done
