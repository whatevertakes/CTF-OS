#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"

cleanup() {
    python3 - "$test_root" <<'PY'
import json
import os
import pathlib
import signal
import sys

for path in pathlib.Path(sys.argv[1]).glob("*.json"):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = int(value["pid"])
        expected = int(value["start_ticks"])
        text = pathlib.Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        if int(fields[19]) == expected:
            os.kill(pid, signal.SIGKILL)
    except (KeyError, OSError, ValueError, json.JSONDecodeError):
        pass
PY
    rm -rf -- "$test_root"
}
trap cleanup EXIT

assert_identity_gone='
import json
import pathlib
import sys
import time

expected = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

def same_process():
    try:
        pid = expected["pid"]
        text = pathlib.Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return (
            fields[0] not in {"Z", "X", "x"}
            and int(fields[19]) == expected["start_ticks"]
        )
    except (OSError, ValueError, IndexError):
        return False

for _ in range(100):
    if not same_process():
        break
    time.sleep(0.03)
else:
    raise AssertionError(expected)
'

# The command and its child both ignore SIGTERM. Timeout cleanup must still
# remove the recorded PID identity and return the stable timed_out result.
term_pid_file="$test_root/term-ignore.json"
term_program='
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen(
    [
        "python3",
        "-c",
        "import signal,time;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        "time.sleep(60)",
    ]
)
text = pathlib.Path(f"/proc/{child.pid}/stat").read_text()
fields = text[text.rfind(")") + 2 :].split()
pathlib.Path(sys.argv[1]).write_text(
    json.dumps({"pid": child.pid, "start_ticks": int(fields[19])}),
    encoding="utf-8",
)
while True:
    time.sleep(1)
'
set +e
CTF_STATE_ROOT="$test_root/state" bash "$repo_root/scripts/ctfwrap" \
    --json --timeout 1 -- python3 -c "$term_program" "$term_pid_file" \
    > "$test_root/term-result"
term_rc=$?
set -e
[[ "$term_rc" -eq 124 ]]
python3 - "$test_root/term-result" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert result["status"] == "timed_out", result
assert result["timed_out"] is True, result
assert result["exit_code"] == 124, result
PY
python3 -c "$assert_identity_gone" "$term_pid_file"

# timeout=0 disables only the deadline. A fast command that starts a detached
# SID must still have that child cleaned before ctfwrap returns completed.
detached_pid_file="$test_root/detached.json"
detached_program='
import json
import pathlib
import subprocess
import sys

child = subprocess.Popen(["sleep", "60"], start_new_session=True)
text = pathlib.Path(f"/proc/{child.pid}/stat").read_text()
fields = text[text.rfind(")") + 2 :].split()
pathlib.Path(sys.argv[1]).write_text(
    json.dumps({"pid": child.pid, "start_ticks": int(fields[19])}),
    encoding="utf-8",
)
'
CTF_STATE_ROOT="$test_root/state" bash "$repo_root/scripts/ctfwrap" \
    --json --timeout 0 -- python3 -c "$detached_program" "$detached_pid_file" \
    > "$test_root/detached-result"
python3 - "$test_root/detached-result" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert result["status"] == "completed", result
assert result["timeout_seconds"] == 0, result
assert result["exit_code"] == 0, result
assert result["stdout_capture_complete"] is False, result
assert result["stderr_capture_complete"] is False, result
assert result["stdout_truncation_known"] is False, result
assert result["stderr_truncation_known"] is False, result
PY
python3 -c "$assert_identity_gone" "$detached_pid_file"

# The timeout parser must reject values above the one-week hard cap without
# allowing Bash integer overflow to turn a huge value into a disabled deadline.
for rejected_timeout in 604801 18446744073709551616; do
    set +e
    CTF_STATE_ROOT="$test_root/rejected-timeout" \
        bash "$repo_root/scripts/ctfwrap" --json \
        --timeout "$rejected_timeout" -- true \
        > "$test_root/rejected-timeout-out" \
        2> "$test_root/rejected-timeout-err"
    rejected_timeout_rc=$?
    set -e
    [[ "$rejected_timeout_rc" -eq 2 ]]
    grep -q -- '--timeout must not exceed 604800 seconds' \
        "$test_root/rejected-timeout-err"
done

# The inclusive upper boundary remains valid and is recorded canonically.
CTF_STATE_ROOT="$test_root/max-timeout" \
    bash "$repo_root/scripts/ctfwrap" --json --timeout 604800 -- true \
    > "$test_root/max-timeout-result"
python3 - "$test_root/max-timeout-result" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert result["status"] == "completed", result
assert result["timeout_seconds"] == 604800, result
PY

# An attacker-controlled FIFO at the lock path must be rejected before open.
fifo_state="$test_root/fifo-state"
mkdir -p -- "$fifo_state/runs"
mkfifo -- "$fifo_state/runs/.lock"
set +e
timeout 3s env CTF_STATE_ROOT="$fifo_state" \
    bash "$repo_root/scripts/ctfwrap" --json --timeout 1 -- true \
    > "$test_root/fifo-out" 2> "$test_root/fifo-err"
fifo_rc=$?
set -e
[[ "$fifo_rc" -ne 0 && "$fifo_rc" -ne 124 ]]
grep -q 'run lock must be a regular file' "$test_root/fifo-err"

# A command can replace its own output pathname after ctfwrap opens the log.
# Result summarization must reject the replacement FIFO without blocking.
fifo_log_state="$test_root/fifo-log-state"
fifo_log_program='
import os
import pathlib

runs_root = pathlib.Path(os.environ["CTF_STATE_ROOT"]) / "runs"
run_dirs = sorted(runs_root.glob("run-*"))
assert len(run_dirs) == 1, run_dirs
stdout_path = run_dirs[0] / "stdout.log"
stdout_path.unlink()
os.mkfifo(stdout_path)
'
timeout 3s env CTF_STATE_ROOT="$fifo_log_state" \
    bash "$repo_root/scripts/ctfwrap" --json --timeout 0 -- \
    python3 -c "$fifo_log_program" > "$test_root/fifo-log-result"
python3 - "$test_root/fifo-log-result" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert result["status"] == "completed", result
assert result["exit_code"] == 0, result
assert result["stdout_error"] == "not_regular", result
assert result["stdout_bytes"] == 0, result
assert result["stdout_summary"] == "", result
PY

# stdout and stderr must both be drained to EOF even after their persisted raw
# prefixes hit independent caps. The summaries still come from the true stream
# tails, and both result.json and meta.json record the truncation.
bounded_state="$test_root/bounded-state"
bounded_program='
import os
import threading

def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view):]

def emit(descriptor, byte, marker):
    for _ in range(128):
        write_all(descriptor, byte * 16384)
    write_all(descriptor, marker)

threads = [
    threading.Thread(target=emit, args=(1, b"O", b"STDOUT-TAIL")),
    threading.Thread(target=emit, args=(2, b"E", b"STDERR-TAIL")),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
'
timeout 10s env CTF_STATE_ROOT="$bounded_state" \
    bash "$repo_root/scripts/ctfwrap" --json --timeout 5 \
    --stdout-limit-bytes 1024 --stderr-limit-bytes 1536 \
    --summary-bytes 32 -- python3 -c "$bounded_program" \
    > "$test_root/bounded-result"
python3 - "$test_root/bounded-result" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["status"] == "completed", result
assert result["exit_code"] == 0, result
assert result["stdout_bytes"] == 128 * 16384 + len(b"STDOUT-TAIL"), result
assert result["stderr_bytes"] == 128 * 16384 + len(b"STDERR-TAIL"), result
assert result["stdout_stored_bytes"] == 1024, result
assert result["stderr_stored_bytes"] == 1536, result
assert result["stdout_truncated"] is True, result
assert result["stderr_truncated"] is True, result
assert result["stdout_truncation_known"] is True, result
assert result["stderr_truncation_known"] is True, result
assert result["stdout_capture_complete"] is True, result
assert result["stderr_capture_complete"] is True, result
assert result["stdout_summary"].endswith("STDOUT-TAIL"), result
assert result["stderr_summary"].endswith("STDERR-TAIL"), result
assert pathlib.Path(result["stdout_path"]).stat().st_size == 1024
assert pathlib.Path(result["stderr_path"]).stat().st_size == 1536

run_dir = pathlib.Path(result["stdout_path"]).parent
meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
assert meta["stdout_limit_bytes"] == 1024, meta
assert meta["stderr_limit_bytes"] == 1536, meta
assert meta["capture"]["stdout"]["truncated"] is True, meta
assert meta["capture"]["stderr"]["truncated"] is True, meta
assert meta["capture"]["stdout"]["stored_bytes"] == 1024, meta
assert meta["capture"]["stderr"]["stored_bytes"] == 1536, meta
PY

# A flag can occur after the persisted stdout prefix and before the retained
# tail. The complete pipe drainer must still record it in a bounded sidecar,
# including when the regex match itself arrives across separate writes.
flag_state="$test_root/flag-state"
flag_program='
import os
import time

assert "CTF_WRAP_FLAG_PATTERNS_JSON" not in os.environ
os.write(1, b"A" * 64)
os.write(1, b"KCTF{mid")
time.sleep(0.05)
os.write(1, b"dle}")
os.write(1, b"B" * 64)
'
CTF_WRAP_FLAG_PATTERNS_JSON='["KCTF\\{[^}]+\\}"]' \
    CTF_STATE_ROOT="$flag_state" \
    bash "$repo_root/scripts/ctfwrap" --json --timeout 5 \
    --stdout-limit-bytes 32 --summary-bytes 8 -- \
    python3 -c "$flag_program" > "$test_root/flag-result"
python3 - "$test_root/flag-result" <<'PY'
import json
import pathlib
import stat
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["status"] == "completed", result
assert result["stdout_truncated"] is True, result
assert "KCTF{middle}" not in result["stdout_summary"], result

run_dir = pathlib.Path(result["stdout_path"]).parent
assert b"KCTF{middle}" not in pathlib.Path(result["stdout_path"]).read_bytes()
sidecar = run_dir / "flag-candidates.jsonl"
assert stat.S_ISREG(sidecar.stat(follow_symlinks=False).st_mode)
records = [
    json.loads(line)
    for line in sidecar.read_text(encoding="utf-8").splitlines()
]
assert records == [
    {
        "schema_version": 1,
        "kind": "flag_candidate",
        "stream": "stdout",
        "value": "KCTF{middle}",
    }
], records

capture = json.loads(
    (run_dir / "stream-capture.json").read_text(encoding="utf-8")
)
scan = capture["flag_scan"]
assert scan["candidate_count"] == 1, scan
assert scan["candidate_chars"] == len("KCTF{middle}"), scan
assert scan["candidate_count_limit"] == 1024, scan
assert scan["candidate_chars_limit"] == 256 * 1024, scan
assert scan["candidate_file_limit_bytes"] == 1024 * 1024, scan
assert scan["candidate_max_chars"] == 1024, scan
assert scan["candidate_max_bytes"] == 4 * 1024, scan
assert scan["rolling_overlap_chars"] == 4 * 1024, scan
assert scan["file_bytes"] == sidecar.stat().st_size, scan
assert scan["complete"] is True, scan
PY

printf 'ctfwrap timeout, detached-session, and special-file regressions: ok\n'
