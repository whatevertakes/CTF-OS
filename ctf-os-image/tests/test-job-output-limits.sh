#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"
job_ids=()

cleanup() {
    for job_id in "${job_ids[@]}"; do
        CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
            --json --grace 0 "$job_id" >/dev/null 2>&1 || true
    done
    rm -rf -- "$test_root"
}
trap cleanup EXIT

program=$'import os, sys\nfd = int(sys.argv[1])\nchunk = b"X" * 65536\nwhile True:\n    os.write(fd, chunk)'

run_overflow_case() {
    local stream="$1"
    local descriptor="$2"
    local stdout_limit=4096
    local stderr_limit=3072
    local expected_limit
    if [[ "$stream" == "stdout" ]]; then
        expected_limit="$stdout_limit"
    else
        expected_limit="$stderr_limit"
    fi

    local launch
    launch="$(
        CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-bg" \
            --json --timeout 10 \
            --stdout-limit-bytes "$stdout_limit" \
            --stderr-limit-bytes "$stderr_limit" -- \
            python3 -c "$program" "$descriptor"
    )"
    local job_id
    job_id="$(
        python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])' \
            <<< "$launch"
    )"
    job_ids+=("$job_id")
    local job_root="$test_root/jobs/$job_id"
    local status=""
    for _ in {1..250}; do
        local stdout_size stderr_size
        stdout_size="$(stat -c %s -- "$job_root/stdout.log")"
        stderr_size="$(stat -c %s -- "$job_root/stderr.log")"
        ((stdout_size <= stdout_limit))
        ((stderr_size <= stderr_limit))
        status="$(
            python3 -c \
                'import json, sys; print(json.load(open(sys.argv[1]))["status"])' \
                "$job_root/status.json"
        )"
        case "$status" in
            completed|failed|timed_out|cancelled|lost) break ;;
        esac
        sleep 0.02
    done
    [[ "$status" == "failed" ]]

    python3 - "$job_root" "$stream" "$expected_limit" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
stream = sys.argv[2]
limit = int(sys.argv[3])
status = json.loads((root / "status.json").read_text(encoding="utf-8"))
capture = json.loads(
    (root / "stream-capture.json").read_text(encoding="utf-8")
)
details = capture["streams"][stream]
assert status["status"] == "failed", status
assert status["exit_code"] == 125, status
assert status["reason_code"] == "output_limit_exceeded", status
assert details["stored_bytes"] == limit, details
assert details["bytes"] > limit, details
assert details["truncated"] is True, details
assert (root / f"{stream}.log").stat().st_size == limit
PY

    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-jobs" \
        --json "$job_id" |
        python3 -c '
import json
import sys
job = json.load(sys.stdin)["jobs"][0]
assert job["status"] == "failed", job
assert job["reason_code"] == "output_limit_exceeded", job
'

    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-log" \
        --json --stream "$stream" --tail-bytes 128 "$job_id" |
        python3 -c '
import json
import sys
details = json.load(sys.stdin)["streams"][sys.argv[1]]
limit = int(sys.argv[2])
assert details["bytes"] > limit, details
assert details["stored_bytes"] == limit, details
assert details["raw_truncated"] is True, details
assert details["tail_truncated"] is True, details
assert details["tail_scope"] == "stored_prefix", details
assert len(details["tail"].encode("utf-8")) <= 128, details
' "$stream" "$expected_limit"
}

run_overflow_case stdout 1
run_overflow_case stderr 2

printf 'background stdout/stderr hard capture limits: ok\n'
