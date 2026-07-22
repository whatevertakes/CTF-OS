---
name: ctf-solve
description: Solve exactly one authorized CTF challenge with Root Sol and optional native Sol, Terra, or Luna workers.
---

# CTF Solve — first to flag

Read `ctf_os/resources/agent-policy.md`, root `AGENTS.md`, and only the selected
category playbook. The current user-opened `/root` session is Sol xhigh and lead
attacker. Python prepares context, private paths, packets, events, and artifacts;
it never starts/stops a native child, authorizes an attack, or submits a flag.

If the user requests a Claude handoff, stop before any new attack, load the
handoff skill, write its single evidence-backed `HANDOFF.md`, and end the Solve.

## Prepare, then attack

Prepare only the selected challenge in this session:

```bash
uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'
```

When the request supplies description, hints, flag format, files, or declared
remote data, pass the bounded challenge-local values with
`--session-input-json`. Preparation returns the challenge context and an empty
worker list. Root immediately runs its best real command or exploit; it does not
wait for a child and no child is mandatory. Whole-contest Intake and Triage are
optional administration and never Solve prerequisites.

## Optional native workers

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
never block creation when omitted.

Call native `spawn_agent` with the returned `spawn_agent_args` exactly, including
`fork_turns="none"`. Use the returned `agent_profile` when the native surface
supports project profiles. Record the actual returned thread ID:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-confirm '<selector>' \
  --contest '<contest>' --lane '<lane-id>' --native-session '<thread-id>'
```

Without a native identity the worker is not `RUNNING`. Record a failed native
start with `worker-spawn-failed`; one retry packet is allowed. Root keeps
attacking throughout.

## Execute, inspect, and replace

Each participant uses real tools and pursues the smallest executable attack.
Workers obey the profile contract in their packet. Useful output is an actual
command, executable artifact, primitive, working PoC, remote result, useful
failure, exact blocker, or flag candidate.

Use `attack-event` only after execution. `sandbox-exec` also attempts a
best-effort command event after the process returns. A logging failure never
blocks or invalidates the completed command. `worker-status` returns compact
per-worker command/output counts and the last event so Root can keep, stop, or
replace a worker without a score or semantic Python gate.

Root calls native `interrupt_agent`, confirms it with `worker-stop-confirm`, then
may use `worker-replace` with any general profile, role, task, and context mode.
A running worker may also be replaced by passing its exact stopped native ID.
Keep Root attacking; never wait only to coordinate.

## Sol max and cutoff

Sol max cannot be requested by `worker-spawn-packet`. From minute 60,
`worker-status` lists a candidate only when one running worker has an executable
partial path, two actual exploit or remote outputs, an exact non-environment
reasoning blocker, and a concrete next attack. Stop that worker and call:

```bash
uv run python -m ctf_os.agent_tools worker-endgame '<selector>' \
  --contest '<contest>' --lane '<lane-id>' --native-stop-session '<thread-id>'
```

Spawn and confirm the returned `ctf_sol_max` packet. Its lease is ten minutes or
two actual attacks. At 90 minutes, call `worker-status`, interrupt every cancel
target, and stop without extension. Preserve the generated compact timeout
handoff. A human continuation starts a fresh attempt.

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
confirm stops, and do no replay that delays display. A human submits. Record
`WRONG` or `ACCEPTED` with `submission-result`; after `WRONG`, Root resumes and
may create any fresh worker.

Attack only this challenge and declared targets. Keep input read-only and every
worker under its private paths. Never access cloud metadata, Docker gateways,
undeclared networks/challenges, the host Docker socket/root, SSH keys, browser
profiles, personal credentials, or personal files.
