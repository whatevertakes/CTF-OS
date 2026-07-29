#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"
job_id=""
zombie_holder_pid=""

cleanup() {
    if [[ -n "$job_id" ]]; then
        CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
            --json --grace 0 "$job_id" >/dev/null 2>&1 || true
    fi
    if [[ -n "$zombie_holder_pid" ]]; then
        kill "$zombie_holder_pid" >/dev/null 2>&1 || true
        wait "$zombie_holder_pid" 2>/dev/null || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

# Both the user command and a child ignore SIGTERM. --grace 0 must force
# SIGKILL across the complete command session.
pid_file="$test_root/forced-kill.json"
program='
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
child_code = """
import signal
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
"""
child = subprocess.Popen(
    ["python3", "-c", child_code],
    preexec_fn=lambda: os.setpgid(0, 0),
)

def identity(pid):
    text = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2 :].split()
    return {
        "pid": pid,
        "sid": int(fields[3]),
        "start_ticks": int(fields[19]),
    }

pathlib.Path(sys.argv[1]).write_text(
    json.dumps([identity(os.getpid()), identity(child.pid)]),
    encoding="utf-8",
)
while True:
    time.sleep(1)
'
launch="$(
    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-bg" \
        --json --timeout 60 -- python3 -c "$program" "$pid_file"
)"
job_id="$(
    python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])' \
        <<< "$launch"
)"
for _ in {1..100}; do
    [[ -s "$pid_file" ]] && break
    sleep 0.02
done
[[ -s "$pid_file" ]] || {
    printf 'forced-kill PID fixture was not created\n' >&2
    exit 1
}

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
    --json --grace 0 "$job_id" >/dev/null

python3 - "$pid_file" "$test_root/jobs/$job_id/status.json" <<'PY'
import json
import pathlib
import sys
import time

recorded = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
status_path = pathlib.Path(sys.argv[2])

def identity(pid):
    try:
        text = pathlib.Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return {
            "state": fields[0],
            "sid": int(fields[3]),
            "start_ticks": int(fields[19]),
        }
    except (OSError, ValueError, IndexError):
        return None

for _ in range(100):
    alive = []
    for expected in recorded:
        current = identity(expected["pid"])
        if (
            current
            and current["state"] not in {"Z", "X", "x"}
            and current["sid"] == expected["sid"]
            and current["start_ticks"] == expected["start_ticks"]
        ):
            alive.append(expected["pid"])
    if not alive:
        break
    time.sleep(0.03)
else:
    raise AssertionError({"SIGTERM_ignoring_processes_still_alive": alive})

status = json.loads(status_path.read_text(encoding="utf-8"))
assert status["status"] == "cancelled", status
assert status["exit_code"] == 130, status
PY
job_id=""

# If a detached supervisor is externally killed, ctf-jobs must reconcile it to
# lost, and ctf-kill must still clean the separately recorded command session.
orphan_file="$test_root/orphan-command.json"
orphan_program='
import json
import pathlib
import subprocess
import sys
import time

child = subprocess.Popen(["sleep", "60"])

def identity(pid):
    text = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2 :].split()
    return {
        "pid": pid,
        "sid": int(fields[3]),
        "start_ticks": int(fields[19]),
    }

pathlib.Path(sys.argv[1]).write_text(
    json.dumps([identity(child.pid)]),
    encoding="utf-8",
)
while True:
    time.sleep(1)
'
launch="$(
    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-bg" \
        --json --timeout 60 -- python3 -c "$orphan_program" "$orphan_file"
)"
job_id="$(
    python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])' \
        <<< "$launch"
)"
for _ in {1..100}; do
    [[ -s "$orphan_file" ]] && break
    sleep 0.02
done
[[ -s "$orphan_file" ]] || {
    printf 'orphan command fixture was not created\n' >&2
    exit 1
}
runner_pid="$(
    python3 -c \
        'import json, sys; print(json.load(open(sys.argv[1]))["runner_pid"])' \
        "$test_root/jobs/$job_id/status.json"
)"
kill -KILL -- "-$runner_pid"
sleep 0.05

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-jobs" \
    --json "$job_id" |
    python3 -c '
import json
import sys
job = json.load(sys.stdin)["jobs"][0]
assert job["status"] == "lost", job
'

result="$(
    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
        --json --grace 0 "$job_id"
)"
python3 - "$result" "$orphan_file" <<'PY'
import json
import pathlib
import sys
import time

result = json.loads(sys.argv[1])
recorded = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
assert result["status"] == "cancelled", result
assert result["action"] == "orphaned_command_cancelled", result

def same_process(expected):
    try:
        text = pathlib.Path(f"/proc/{expected['pid']}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return (
            fields[0] not in {"Z", "X", "x"}
            and int(fields[3]) == expected["sid"]
            and int(fields[19]) == expected["start_ticks"]
        )
    except (OSError, ValueError, IndexError):
        return False

for _ in range(100):
    alive = [process["pid"] for process in recorded if same_process(process)]
    if not alive:
        break
    time.sleep(0.03)
else:
    raise AssertionError({"orphan_command_processes_still_alive": alive})
PY
job_id=""

# Build a real zombie and point stale running records at it. A zombie still has
# /proc identity and accepts kill -0, but must be treated as dead by lifecycle
# reconciliation so detached/orphaned jobs cannot remain running forever.
zombie_file="$test_root/zombie.json"
python3 - "$zombie_file" <<'PY' &
import json
import os
import pathlib
import sys
import time

child = os.fork()
if child == 0:
    os._exit(0)

stat_path = pathlib.Path(f"/proc/{child}/stat")
for _ in range(100):
    text = stat_path.read_text()
    fields = text[text.rfind(")") + 2 :].split()
    if fields[0] == "Z":
        pathlib.Path(sys.argv[1]).write_text(
            json.dumps(
                {
                    "pid": child,
                    "start_ticks": int(fields[19]),
                    "state": fields[0],
                }
            ),
            encoding="utf-8",
        )
        break
    time.sleep(0.01)
else:
    raise RuntimeError("child did not enter zombie state")

time.sleep(60)
PY
zombie_holder_pid=$!
for _ in {1..100}; do
    [[ -s "$zombie_file" ]] && break
    sleep 0.02
done
[[ -s "$zombie_file" ]] || {
    printf 'zombie fixture was not created\n' >&2
    exit 1
}

python3 - "$test_root" "$zombie_file" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]) / "jobs"
zombie = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
for job_id in ("job-99999998", "job-99999999"):
    directory = root / job_id
    directory.mkdir(parents=True)
    (directory / "stdout.log").touch()
    (directory / "stderr.log").touch()
    (directory / "meta.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "job_id": job_id,
                "name": "zombie-fixture",
                "created_at": "2020-01-01T00:00:00+00:00",
                "timeout_seconds": 60,
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
                "status": "running",
                "runner_pid": zombie["pid"],
                "pgid": zombie["pid"],
                "pid_start_ticks": zombie["start_ticks"],
                "started_at": "2020-01-01T00:00:00+00:00",
                "finished_at": None,
                "exit_code": None,
                "timed_out": False,
                "cancelled": False,
            }
        ),
        encoding="utf-8",
    )
PY

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-jobs" \
    --json job-99999999 |
    python3 -c '
import json
import sys
job = json.load(sys.stdin)["jobs"][0]
assert job["status"] == "lost", job
'

timeout 3s env CTF_STATE_ROOT="$test_root" \
    bash "$repo_root/scripts/ctf-kill" --json job-99999998 |
    python3 -c '
import json
import sys
result = json.load(sys.stdin)
assert result["status"] == "cancelled", result
assert result["action"] == "process_already_gone", result
'

printf 'forced SIGKILL and zombie/lost lifecycle regressions: ok\n'
