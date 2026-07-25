#!/usr/bin/env bash
set -Eeuo pipefail

profile="${1:?usage: verify-python.sh PROFILE}"
allowlist="/opt/ctf-os/pip-check-allowlists/${profile}.txt"
actual="$(mktemp)"
expected="$(mktemp)"
sorted_actual="$(mktemp)"
trap 'rm -f "$actual" "$expected" "$sorted_actual"' EXIT

status=0
python3 -m pip check >"$actual" 2>&1 || status=$?

if [[ "$status" -eq 0 ]]; then
  if [[ -s "$allowlist" ]]; then
    echo "pip check succeeded, but the ${profile} allowlist is now stale:" >&2
    cat "$allowlist" >&2
    exit 1
  fi
  exit 0
fi

if [[ ! -s "$allowlist" ]]; then
  cat "$actual" >&2
  exit "$status"
fi

# Debian's AWS/Azure packages deliberately run with only Debian's dist-packages,
# while analysis libraries use the separately locked /usr/local environment.
# Their distro metadata still appears to the global pip command. Accept only the
# exact, reviewed set; a new or resolved mismatch fails the image build.
LC_ALL=C sort "$allowlist" >"$expected"
LC_ALL=C sort "$actual" >"$sorted_actual"
if ! diff -u "$expected" "$sorted_actual"; then
  echo "unexpected Python dependency state for profile ${profile}" >&2
  exit 1
fi
echo "accepted reviewed Debian CLI metadata mismatches for profile ${profile}" >&2
