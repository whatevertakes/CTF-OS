#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
jobs_root="$test_root/jobs"
mkdir -p -- "$jobs_root"

# Allocation locks and counters are under the writable work tree. A FIFO lock
# must fail before open instead of stalling job creation.
mkfifo -- "$jobs_root/.lock"
set +e
timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-bg" --json --timeout 1 -- true \
    > "$test_root/bg-out" 2> "$test_root/bg-err"
bg_rc=$?
set -e
[[ "$bg_rc" -ne 0 && "$bg_rc" -ne 124 ]]
grep -q 'job lock must be a regular file' "$test_root/bg-err"
unlink -- "$jobs_root/.lock"

python3 - "$jobs_root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for suffix in (91, 92, 93, 94):
    job_id = f"job-{suffix:08d}"
    directory = root / job_id
    directory.mkdir()
    (directory / "stderr.log").touch()
    (directory / "meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "job_id": job_id,
                "name": "state-safety-fixture",
                "created_at": "2020-01-01T00:00:00+00:00",
                "timeout_seconds": 1,
                "stdout_path": str(directory / "stdout.log"),
                "stderr_path": str(directory / "stderr.log"),
            }
        ),
        encoding="utf-8",
    )
    (directory / "status.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "job_id": job_id,
                "status": "completed",
                "runner_pid": None,
                "pgid": None,
                "pid_start_ticks": None,
                "exit_code": 0,
                "timed_out": False,
                "cancelled": False,
            }
        ),
        encoding="utf-8",
    )
PY

# Log tails reject special files before open.
log_job="job-00000091"
mkfifo -- "$jobs_root/$log_job/stdout.log"
set +e
timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-log" --json --stream stdout "$log_job" \
    > "$test_root/log-out" 2> "$test_root/log-err"
log_rc=$?
set -e
[[ "$log_rc" -ne 0 && "$log_rc" -ne 124 ]]
grep -q 'log must be a regular file' "$test_root/log-err"

# Status reconciliation treats an unsafe status file as lost and atomically
# replaces it; it never opens the FIFO.
jobs_job="job-00000092"
unlink -- "$jobs_root/$jobs_job/status.json"
mkfifo -- "$jobs_root/$jobs_job/status.json"
timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-jobs" --json "$jobs_job" |
    python3 -c '
import json
import sys
job = json.load(sys.stdin)["jobs"][0]
assert job["status"] == "lost", job
'
[[ -f "$jobs_root/$jobs_job/status.json" && ! -L "$jobs_root/$jobs_job/status.json" ]]

# Existing special cancel markers are rejected rather than write-opened.
marker_job="job-00000093"
mkfifo -- "$jobs_root/$marker_job/cancel.requested"
set +e
timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-kill" --json "$marker_job" \
    > "$test_root/marker-out" 2> "$test_root/marker-err"
marker_rc=$?
set -e
[[ "$marker_rc" -ne 0 && "$marker_rc" -ne 124 ]]
grep -q 'cancel marker must be a regular file' "$test_root/marker-err"

# An unsafe status file is replaced with a bounded cancelled result promptly.
kill_job="job-00000094"
unlink -- "$jobs_root/$kill_job/status.json"
mkfifo -- "$jobs_root/$kill_job/status.json"
timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-kill" --json "$kill_job" |
    python3 -c '
import json
import sys
result = json.load(sys.stdin)
assert result["status"] == "cancelled", result
assert result["action"] == "cancelled_before_start", result
'
[[ -f "$jobs_root/$kill_job/status.json" && ! -L "$jobs_root/$kill_job/status.json" ]]

# Plain table output must neutralize every user-controlled cell. JSON mode
# remains structured and therefore preserves the original values.
terminal_job="job-00000091"
python3 - "$jobs_root/$terminal_job/meta.json" \
    "$jobs_root/$terminal_job/status.json" <<'PY'
import json
import pathlib
import sys

meta_path = pathlib.Path(sys.argv[1])
status_path = pathlib.Path(sys.argv[2])
meta = json.loads(meta_path.read_text(encoding="utf-8"))
status = json.loads(status_path.read_text(encoding="utf-8"))
meta["name"] = "name\x1b[31m\tline\nnext\u009b"
status["status"] = "run\x1b[2J\tline\nnext\u009b"
status["exit_code"] = "exit\x07code"
status["runner_pid"] = "pid\x1b[H"
meta_path.write_text(json.dumps(meta), encoding="utf-8")
status_path.write_text(json.dumps(status), encoding="utf-8")
PY

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-jobs" \
    --all "$terminal_job" > "$test_root/terminal-table"
python3 - "$test_root/terminal-table" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in data, data
assert b"\x07" not in data, data
assert b"\x09" not in data, data
assert data.count(b"\n") == 2, data
assert b"run\\x1b[2J line next\\x9b" in data, data
assert b"exit\\x07code" in data, data
assert b"pid\\x1b[H" in data, data
assert b"name\\x1b[31m line next\\x9b" in data, data
PY

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-jobs" \
    --json "$terminal_job" |
    python3 -c '
import json
import sys
job = json.load(sys.stdin)["jobs"][0]
assert job["name"] == "name\x1b[31m\tline\nnext\u009b", job
assert job["status"] == "run\x1b[2J\tline\nnext\u009b", job
assert job["exit_code"] == "exit\x07code", job
assert job["runner_pid"] == "pid\x1b[H", job
'

printf 'job state special-file and terminal-safety regressions: ok\n'
