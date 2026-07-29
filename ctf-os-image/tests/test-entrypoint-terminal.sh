#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

challenge_dir="${test_root}/challenge"
work_dir="${test_root}/work"
mkdir -p -- "${challenge_dir}" "${work_dir}"
hostile_name=$'bad\033]0;CTFOS-PWN\007'
mkfifo -- "${challenge_dir}/${hostile_name}"

set +e
CTF_CHALLENGE_DIR="${challenge_dir}" \
CTF_WORK_DIR="${work_dir}" \
CTF_UNSAFE_ALLOW_WRITABLE_CHALLENGE=1 \
  bash "${repo_root}/scripts/entrypoint.sh" true \
  >"${test_root}/stdout" 2>"${test_root}/stderr"
status=$?
set -e

[[ "${status}" -ne 0 ]]
python3 - "${test_root}/stderr" <<'PY'
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in raw, raw
assert b"\x07" not in raw, raw
assert b"CTFOS-PWN" in raw, raw
assert b"unsupported challenge inputs" in raw, raw
PY

printf 'entrypoint terminal control escaping: ok\n'
