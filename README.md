# CTF-OS

CTF-OS is a one-challenge, Sol-native first-to-flag environment for authorized
CTFs. It preserves challenge/attempt isolation, read-only inputs, mandatory
category sandboxes, declared-target scope, process/GPU resources, manual
submission, and manual Claude handoff.

```text
prepare selected challenge
→ create/prove Root category sandbox
→ Root Sol xhigh attacks through sandbox-exec
→ optional 0–3 sandbox-backed Sol/Terra/Luna native workers
→ actual commands, artifacts, and attack mutation
→ declared remote
→ first valid target-observed flag
→ sibling cancellation and human submission
```

There is one live Solve engine. The selected challenge owns the machine and
session until a flag, the 90-minute cutoff, or a Claude handoff. Challenge tools
never run directly on the host.

## Setup

```bash
uv sync --frozen
bash sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
```

`doctor` checks every category image and its required tools. A Solve does not
silently fall back to host tools when an image or Docker runtime is unavailable.

## Root Solve flow

Initialize a contest workspace if needed, then prepare only the selected problem:

```bash
uv run python -m ctf_os.agent_tools init-contest 'My CTF 2026'
uv run python -m ctf_os.agent_tools prepare-challenge 'web/Challenge' --contest 'My CTF 2026'
```

Preparation returns direct attack context and zero native workers. It
inspects local images without pulling and automatically reuses or creates the
Root sandbox. The recommended category image is preferred and
`ctf-os-sandbox:base` is the fallback. A resource-admission failure gets one
bounded retry with the `light` profile. `root_sandbox.exec_command_prefix` is
the immediate execution entry point when `root_sandbox.status` is `READY`:

```bash
# Append the real command to the prefix returned by prepare-challenge, for example:
uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<run_root>/workers/root/sandbox.json' \
  --session-id sol-main --session-role sol --parent-session-id sol-main \
  -- file /challenge/app.py
```

The decision and recovery details are persisted in `<run>/ROOT-SANDBOX.json` and
included as `execution_environment` in `SOLVE-LAUNCH.json`. If neither image is
available, preparation does not run challenge artifacts on the host; it returns
the exact `sandbox/build-images.sh <profile> base` command. If a managed local
service is not running, start it with the controller commands and recover the
Root sandbox with `sandbox-create --branch root --session-role sol --service`.
Use `--no-auto-sandbox` only when intentionally managing the Root sandbox
manually.

Every analyzer, debugger, compiler, script, exploit, and remote request runs
through the returned metadata. Inside the image, `/challenge` is read-only,
`/work` is mutable, and durable output goes to `/artifacts`. Host execution is
reserved for CTF-OS controller commands.

## Sandbox-backed native workers

Root begins its own attack immediately through the ready sandbox. When useful,
Root creates one optional packet:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-packet 'web/Challenge' \
  --contest 'My CTF 2026' --model-profile terra-high --role builder \
  --context-mode directed --task 'Turn the current request path into remote exploit.py'
```

Profiles are `sol-xhigh` for a new attack mechanism, `terra-high` for an
executable artifact, and `luna-high` for bounded mechanical work. A packet does
not start a model. Root reads its `lane_id`, `agent_profile`,
`spawn_agent_args`, and `worker_paths.metadata_path`, creates and probes the
lane sandbox, and only then calls native `spawn_agent`:

```bash
uv run python -m ctf_os.agent_tools sandbox-create 'web/Challenge' \
  --contest 'My CTF 2026' --branch terra-1 \
  --session-id terra-1 --session-role child --parent-session-id sol-main

uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<run_root>/workers/terra-1/sandbox.json' \
  --session-id terra-1 --session-role child --parent-session-id sol-main \
  -- true
```

Root passes the packet's `agent_profile` and `spawn_agent_args` to native
`spawn_agent` with `fork_turns="none"`, then records the returned identity:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-confirm 'web/Challenge' \
  --contest 'My CTF 2026' --lane terra-1 --native-session '<thread-id>'
```

Only a lane with both a live category sandbox and an actual native identity is a
running attack worker. Root plus at most three native children keeps model
concurrency at four. Each worker executes exclusively through its own metadata
path and exports durable artifacts before sharing them.

## Events, replacement, and cleanup

`SWARM.json` holds compact attempt/worker state and `ATTACK_EVENTS.jsonl` holds
post-execution facts. `sandbox-exec` records completed commands best-effort;
event-write failure cannot block an already completed attack.

`worker-status` exposes compact real-output history. Root may interrupt an
unproductive worker, confirm the stop, export useful artifacts, clean its
sandbox, and create a fresh category sandbox for a replacement. Python does not
score role quality.

After minute 60, `worker-endgame` may replace one qualified worker with
`ctf_sol_max`. Qualification requires an executable partial path, two actual
attack outputs, an exact non-environment reasoning blocker, and a concrete next
attack. Max also receives a live category sandbox before native spawn. The lease
is ten minutes or two attacks. The 90-minute cutoff writes
`artifacts/TIMEOUT_HANDOFF.md`, returns cancel targets, cleans runtime resources,
and never extends.

## Flag and isolation

A usable payload or meaningful local response is enough to attack the declared
remote. `flag-found` accepts only a format-valid non-placeholder candidate that
appears in actual target output with an exact executed command. It chooses the
first winner and returns native sibling cancel targets. CTF-OS never submits;
`submission-result` records human `wrong` or `accepted` feedback.

- Keep the Root sandbox alive after a candidate so `wrong` resumes immediately.
- On `accepted`, timeout, or Claude handoff, export needed artifacts and clean all
  CTF-OS-owned worker/Root sandboxes, services, processes, and resources.
- A fresh attempt inherits no artifact, cache, native identity, sandbox, service,
  or solver state.
- Input is read-only; each lane writes only in private `work`, `evidence`, and
  `artifacts` paths.
- Sandboxes enforce organizer-declared target scope and block host/private data.
- Shared service and global resource changes remain Root-only.

Whole-contest Intake and Triage run only when explicitly requested and do not
affect a Solve. On “클로드 구조대 준비해라”, stop the attack, use the handoff
skill to write one evidence-backed `rescue/<contest>/<challenge>/HANDOFF.md`,
then terminate and clean the current CTF-OS runtime.
