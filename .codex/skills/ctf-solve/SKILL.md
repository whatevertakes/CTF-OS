---
name: ctf-solve
description: Solve exactly one authorized CTF challenge with Root Sol and optional native Sol, Terra, or Luna workers.
---

# CTF Solve — first to flag

Read `ctf_os/resources/agent-policy.md`, root `AGENTS.md`, and only the selected
category playbook. The current user-opened `/root` session is Sol xhigh and lead
attacker. Python prepares context, private paths, category sandboxes, packets,
events, and artifacts; it never starts/stops a native child, authorizes an
attack, or submits a flag.

If the user requests a Claude handoff, stop before any new attack, load the
handoff skill, write its single evidence-backed `HANDOFF.md`, terminate native
workers, clean CTF-OS sandboxes/services, and end the Solve.

## Prepare and bootstrap the Root sandbox

Prepare only the selected challenge in this session:

```bash
uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'
```

When the request supplies description, hints, flag format, files, or declared
remote data, pass the bounded challenge-local values with
`--session-input-json`. Whole-contest Intake and Triage are optional
administration and never Solve prerequisites.

Read `run_root`, `recommended_environment.image`, and `service_plan` from the
returned JSON. Before inspecting a challenge file, running recon, or executing
an exploit, Root MUST have a live category sandbox at:

```text
<run_root>/workers/root/sandbox.json
```

If preparation reports a Dockerfile/Compose service plan, Root first inspects
and reuses a healthy service or runs the existing `service-build` and
`service-start` controller commands. Root owns that shared service lifecycle.
Then create the Root sandbox; image selection is automatic from the selected
category and preflight recommendation:

```bash
uv run python -m ctf_os.agent_tools sandbox-create '<selector>' \
  --contest '<contest>' --branch root \
  --session-id root --session-role child --parent-session-id sol-main
```

On a resumed attempt, if the metadata file already exists, first prove that the
container is live with `sandbox-exec ... -- true` and reuse it. If that probe
fails, run `sandbox-cleanup` for the exact metadata, run `sandbox-gc` if needed,
and recreate it. Never fall back to host challenge tools because sandbox
bootstrap failed. Report the exact blocker instead.

Root now attacks immediately. Every challenge inspection, analyzer, compiler,
debugger, script, payload, solver, and remote request MUST run through:

```bash
uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<run_root>/workers/root/sandbox.json' \
  --session-id sol-main --session-role sol --parent-session-id sol-main \
  -- <command> [args...]
```

Inside the container, input is `/challenge` read-only, mutable work is `/work`,
evidence is `/evidence`, and durable attack output is `/artifacts`. Only
CTF-OS controller commands such as `worker-*`, `sandbox-*`, `service-*`,
`flag-found`, and `submission-result` run on the host. Direct host execution of
challenge tools is forbidden.

Preparation returns an empty worker list. Root does not wait for a child and no
child is mandatory.

## Optional native workers with mandatory sandboxes

Root may create zero to three workers at any time. Choose directly:

```text
new attack mechanism or hard alternate reasoning → sol-xhigh
concrete direction needs executable code          → terra-high
bounded repetitive/mechanical work                → luna-high
```

Create one packet with only profile, role, task, and context mode:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-packet '<selector>' \
  --contest '<contest>' --model-profile terra-high --role builder \
  --context-mode directed --task-file /tmp/task.txt \
  --facts-json '["format string controls printf","offset candidate 8"]'
```

Use `fresh` for a Sol perspective that receives only the problem, prepared input,
and declared remote. Use `directed` for a builder, mechanical task, or failure
analysis; it may include `--facts-json`, `--failure-command-json`,
`--failure-output`, `--artifact`, and `--exact-blocker`. These are optional and
never block packet creation.

Read the returned `lane_id`, `agent_profile`, `spawn_agent_args`, and
`worker_paths.metadata_path`. Before native `spawn_agent`, Root MUST create and
probe that lane's category sandbox:

```bash
uv run python -m ctf_os.agent_tools sandbox-create '<selector>' \
  --contest '<contest>' --branch '<lane-id>' \
  --session-id '<lane-id>' --session-role child --parent-session-id sol-main

uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<worker_paths.metadata_path>' \
  --session-id '<lane-id>' --session-role child --parent-session-id sol-main \
  -- true
```

A worker may be spawned only after that probe succeeds. Call native
`spawn_agent` with the returned `agent_profile` and `spawn_agent_args` exactly,
including `fork_turns="none"`. The child must use its packet's metadata path and
must execute every challenge command with `sandbox-exec`; it may not use host
challenge tools. Record the actual returned thread ID:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-confirm '<selector>' \
  --contest '<contest>' --lane '<lane-id>' --native-session '<thread-id>'
```

Without a native identity the worker is not `RUNNING`. Record a failed native
start with `worker-spawn-failed`; one retry packet is allowed. If native start is
abandoned, clean that lane's sandbox. Root keeps attacking in its own sandbox
throughout.

## Execute, inspect, and replace

Each participant uses real tools in its assigned category image and pursues the
smallest executable attack. Useful output is an actual command, executable
artifact, primitive, working PoC, remote result, useful failure, exact blocker,
or flag candidate.

Use `attack-event` only after execution. `sandbox-exec` also attempts a
best-effort command event after the process returns. A logging failure never
blocks or invalidates the completed command. `worker-status` returns compact
per-worker command/output counts and the last event so Root can keep, stop, or
replace a worker without a score or semantic Python gate.

Before a worker returns an artifact, it runs `sandbox-export` for its own exact
metadata so the artifact exists under its run-relative
`workers/<lane-id>/artifacts/` path.

Root calls native `interrupt_agent`, confirms it with `worker-stop-confirm`,
exports any useful artifacts, and runs `sandbox-cleanup` for the stopped lane.
It may then call `worker-replace`; after receiving the replacement lane ID it
creates and probes the replacement sandbox before native spawn. Keep Root
attacking; never wait only to coordinate.

## Sol max and cutoff

Sol max cannot be requested by `worker-spawn-packet`. From minute 60,
`worker-status` lists a candidate only when one running worker has an executable
partial path, two actual exploit or remote outputs, an exact non-environment
reasoning blocker, and a concrete next attack. Stop and clean that worker, then
call:

```bash
uv run python -m ctf_os.agent_tools worker-endgame '<selector>' \
  --contest '<contest>' --lane '<lane-id>' --native-stop-session '<thread-id>'
```

Create and probe the returned Max lane sandbox exactly like every other worker,
then spawn and confirm `ctf_sol_max`. Its lease is ten minutes or two actual
attacks. At 90 minutes, call `worker-status`, interrupt every cancel target,
confirm stops, export useful artifacts, clean all worker and Root sandboxes,
stop the managed service, and do not extend. Preserve the generated compact
timeout handoff. A human continuation starts a fresh attempt.

## First flag wins

Any worker sends a candidate, exact command, and actual target output to Root.
Root validates and records it:

```bash
uv run python -m ctf_os.agent_tools flag-found '<selector>' \
  --contest '<contest>' --lane '<lane-id-or-root>' --candidate '<flag>' \
  --observed-output '<actual-output>' --artifact '<run-relative-artifact>' \
  --source '<challenge-or-declared-target>' -- '<exact-command>'
```

Display the returned flag block immediately. Interrupt every returned sibling,
confirm stops, and do no replay that delays display. Keep the Root sandbox alive
until the human records `WRONG` or `ACCEPTED`. After `WRONG`, Root resumes in the
same live Root sandbox and may create a fresh sandbox-backed worker. After
`ACCEPTED`, export needed artifacts and clean all CTF-OS worker/Root sandboxes,
services, processes, and resources. A human submits; CTF-OS never auto-submits.

Attack only this challenge and declared targets. Keep input read-only and every
participant in its category sandbox. Never access cloud metadata, Docker
gateways, undeclared networks/challenges, the host Docker socket/root, SSH keys,
browser profiles, personal credentials, or personal files.
