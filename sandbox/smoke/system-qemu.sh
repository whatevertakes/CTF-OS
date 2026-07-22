#!/usr/bin/env bash
set -Eeuo pipefail

for emulator in qemu-system-x86_64 qemu-system-aarch64 qemu-system-riscv64; do
  "$emulator" --version
  "$emulator" -machine help | grep -qE '^none[[:space:]]'
  log="$(mktemp "/tmp/ctf-os-${emulator}.XXXXXX")"
  if timeout 2s "$emulator" -machine none -nodefaults -nographic -S >"$log" 2>&1; then
    echo "$emulator exited instead of remaining in a valid non-booting start" >&2
    rm -f -- "$log"
    exit 1
  else
    status=$?
  fi
  if [[ "$status" -ne 124 ]]; then
    cat "$log" >&2
    rm -f -- "$log"
    echo "$emulator failed startup with status $status" >&2
    exit 1
  fi
  rm -f -- "$log"
  printf '%s=TCG_START_OK\n' "$emulator"
done

qemu-img --version
