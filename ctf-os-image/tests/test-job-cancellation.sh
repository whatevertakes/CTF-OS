#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d)"
job_id=""

cleanup() {
    if [[ -n "$job_id" ]]; then
        CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
            --json --grace 0 "$job_id" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT

pid_file="$test_root/descendants.json"
program='
import json
import os
import pathlib
import subprocess
import sys
import time

def identity(pid):
    text = pathlib.Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2 :].split()
    return {
        "pid": pid,
        "pgrp": int(fields[2]),
        "sid": int(fields[3]),
        "start_ticks": int(fields[19]),
    }

same_group = subprocess.Popen(["sleep", "60"])
new_group = subprocess.Popen(
    ["sleep", "60"],
    preexec_fn=lambda: os.setpgid(0, 0),
)
rows = [identity(os.getpid()), identity(same_group.pid), identity(new_group.pid)]
pathlib.Path(sys.argv[1]).write_text(json.dumps(rows), encoding="utf-8")
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
    printf 'descendant PID fixture was not created\n' >&2
    exit 1
}

CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-kill" \
    --json --grace 1 "$job_id" >/dev/null

python3 - "$pid_file" "$test_root/jobs/$job_id/status.json" <<'PY'
import json
import pathlib
import sys
import time

recorded = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
status = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
session_id = status["command_sid"]
session_start_ticks = status["command_pid_start_ticks"]

def identity(pid):
    try:
        text = pathlib.Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return {
            "sid": int(fields[3]),
            "start_ticks": int(fields[19]),
        }
    except (OSError, ValueError, IndexError):
        return None

for _ in range(100):
    recorded_alive = [
        process
        for process in recorded
        if identity(process["pid"])
        == {
            "sid": process["sid"],
            "start_ticks": process["start_ticks"],
        }
    ]
    session_members = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        process = identity(int(entry.name))
        if (
            process
            and process["sid"] == session_id
            and process["start_ticks"] >= session_start_ticks
        ):
            session_members.append(int(entry.name))
    if not recorded_alive and not session_members:
        break
    time.sleep(0.03)
else:
    raise AssertionError(
        {
            "recorded_pid_identities_still_alive": recorded_alive,
            "command_session_members_still_alive": session_members,
        }
    )

assert status["status"] == "cancelled", status
assert status["exit_code"] == 130, status
PY

# A user command may daemonize and exit immediately after release. The
# supervisor must already know the session identity and clean the daemon.
job_id=""
daemon_pid_file="$test_root/fast-daemon.json"
daemon_program='
import json
import pathlib
import subprocess
import sys

child = subprocess.Popen(["sleep", "60"])
text = pathlib.Path(f"/proc/{child.pid}/stat").read_text()
fields = text[text.rfind(")") + 2 :].split()
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(
        {
            "pid": child.pid,
            "sid": int(fields[3]),
            "start_ticks": int(fields[19]),
        }
    ),
    encoding="utf-8",
)
'
launch="$(
    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-bg" \
        --json --timeout 60 -- python3 -c "$daemon_program" "$daemon_pid_file"
)"
job_id="$(
    python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])' \
        <<< "$launch"
)"
for _ in {1..100}; do
    [[ -s "$daemon_pid_file" ]] && break
    sleep 0.02
done
[[ -s "$daemon_pid_file" ]] || {
    printf 'fast-daemon PID fixture was not created\n' >&2
    exit 1
}

python3 - "$daemon_pid_file" "$test_root/jobs/$job_id/status.json" <<'PY'
import json
import pathlib
import sys
import time

daemon = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
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
    status = json.loads(status_path.read_text(encoding="utf-8"))
    process = identity(daemon["pid"])
    same_process = (
        process
        and process["state"] not in {"Z", "X", "x"}
        and process["sid"] == daemon["sid"]
        and process["start_ticks"] == daemon["start_ticks"]
    )
    if status["status"] == "completed" and not same_process:
        break
    time.sleep(0.03)
else:
    raise AssertionError({"status": status, "daemon_identity": process})
PY

# A fast successful job with a long timeout must reap its watcher immediately;
# no watcher or child sleep may remain in the supervisor session.
job_id=""
launch="$(
    CTF_STATE_ROOT="$test_root" bash "$repo_root/scripts/ctf-bg" \
        --json --timeout 60 -- true
)"
job_id="$(
    python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])' \
        <<< "$launch"
)"
status_path="$test_root/jobs/$job_id/status.json"
for _ in {1..100}; do
    current_status="$(
        python3 -c \
            'import json, sys; print(json.load(open(sys.argv[1]))["status"])' \
            "$status_path"
    )"
    [[ "$current_status" == "completed" ]] && break
    sleep 0.02
done

python3 - "$status_path" <<'PY'
import json
import pathlib
import sys
import time

status = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert status["status"] == "completed", status
session_id = status["runner_pid"]
session_start_ticks = status["pid_start_ticks"]

def is_matching_member(entry):
    try:
        text = (entry / "stat").read_text()
        fields = text[text.rfind(")") + 2 :].split()
        return (
            fields[0] not in {"Z", "X", "x"}
            and int(fields[3]) == session_id
            and int(fields[19]) >= session_start_ticks
        )
    except (OSError, ValueError, IndexError):
        return False

for _ in range(100):
    members = [
        int(entry.name)
        for entry in pathlib.Path("/proc").iterdir()
        if entry.name.isdigit() and is_matching_member(entry)
    ]
    if not members:
        break
    time.sleep(0.03)
else:
    raise AssertionError({"watcher_or_supervisor_session_members": members})
PY

printf 'job cancellation/session and timeout-watcher regressions: ok\n'
