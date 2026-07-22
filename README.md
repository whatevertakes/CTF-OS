# CTF-OS

CTF-OS is a Sol-native first-to-flag execution environment for authorized CTF
challenges. It preserves challenge/attempt isolation, read-only inputs, category
sandboxes, declared-target network scope, GPU and process resources, minimal
evidence, manual flag submission, and manual Claude handoff.

The live Solve engine is intentionally singular:

```text
challenge-local prepare
→ Root + independent + exploit-first + tool-driven
→ actual attack commands and payload mutation
→ declared remote
→ first valid flag displayed immediately
→ sibling cancellation
```

There are no solve modes, tiers, evidence admissions, primitive confirmation
steps, PoC/remote approvals, or alternate evaluation engines.

## Setup

```bash
uv sync --frozen
uv run python -m ctf_os.agent_tools doctor
```

Category images are built with:

```bash
bash sandbox/build-images.sh
```

## Standard flow

Initialize a contest workspace if needed:

```bash
uv run python -m ctf_os.agent_tools init-contest 'My CTF 2026'
```

Then ask the current Sol session to solve one challenge. Solve uses the challenge
description, hint, supplied files, and organizer-declared remote from that same
request. Whole-contest Intake and Triage are not prerequisites.

Internally, the skill runs:

```bash
uv run python -m ctf_os.agent_tools prepare-challenge 'web/Challenge' --contest 'My CTF 2026'
```

The result includes `spawn_queue` with exactly three native packets. The skill
calls `spawn_agent` for every packet with `fork_turns=none` before further recon,
then records returned thread IDs:

```bash
uv run python -m ctf_os.agent_tools swarm-spawn-confirm 'web/Challenge' \
  --contest 'My CTF 2026' --lane independent --native-session '<thread-id>'
```

Only a returned native identity becomes `RUNNING`. A failure is recorded with
`swarm-spawn-failed` and may be retried once; Root keeps attacking.

## Attack events

`SWARM.json` is the compact attempt state and `ATTACK_EVENTS.jsonl` stores
post-execution facts. Useful event types are `COMMAND_EXECUTED`,
`ATTACK_PATH_FOUND`, `EXPLOIT_ATTEMPTED`, `PRIMITIVE`, `POC`, `WORKING_POC`,
`REMOTE_ATTEMPT`, `REMOTE_RESULT`, `USEFUL_FAILURE`, and `BLOCKER`.

```bash
uv run python -m ctf_os.agent_tools attack-event 'web/Challenge' \
  --contest 'My CTF 2026' --lane exploit-first --type PRIMITIVE \
  --summary 'request controls template path' --observed-output 'HTTP 200 ...' \
  --next-attack 'send traversal payload' -- python3 probe.py
```

Events never authorize attacks. `sandbox-exec` runs first and only then attempts
a best-effort command event, so a logging failure cannot prevent execution.

## Remote and flag fast path

A sendable payload or one meaningful local response is enough to attack a
declared remote. No clean replay or approval is required.

When Root sees a candidate in actual challenge output:

```bash
uv run python -m ctf_os.agent_tools flag-found 'web/Challenge' \
  --contest 'My CTF 2026' --lane exploit-first --candidate 'CTF{...}' \
  --observed-output '...CTF{...}...' --artifact 'workers/exploit-first/artifacts/solve.py' \
  --source 'declared remote' -- python3 solve.py
```

The command validates format/placeholder/output presence, chooses the first
winner, returns all native cancel targets, and prints a ready-to-display flag
block. CTF-OS never submits the flag. Human feedback is recorded with:

```bash
uv run python -m ctf_os.agent_tools submission-result 'web/Challenge' \
  --contest 'My CTF 2026' --run-id '<run-id>' --candidate 'CTF{...}' --result accepted
```

`wrong` discards only that candidate and returns a fresh striker packet.

## Replacement and deadline

`swarm-status` identifies up to two low-yield 30-minute lanes and one eligible
60-minute reasoning endgame. Stop a running native child before `swarm-replace`;
replacement count is bounded only by the 90-minute deadline and native
concurrency. At 90 minutes status writes `artifacts/TIMEOUT_HANDOFF.md`, returns
cancel targets, and never extends automatically.

## Isolation and execution

- Input is mounted read-only from the selected challenge workspace.
- Each worker writes only to private `work`, `evidence`, and `artifacts` paths.
- Sandboxes enforce organizer-declared remote scope and block host/private data.
- Shared service and global scheduler operations are Root-only.
- Long symbolic/fuzz/forensic/crypto/AI workloads use real resource/process
  management; short probes and PoCs run immediately.
- A new attempt never inherits artifacts, cache, child/session, sandbox, or
  solver state from another attempt.

Useful low-level commands include `sandbox-create`, `sandbox-exec`,
`sandbox-cleanup`, service lifecycle commands, resource commands, `oast-*`,
`repair-run`, and optional `replay`. Replay is post-result tooling and never part
of the live remote/flag path.

## Optional administration and handoff

Run `intake` or `triage-*` only for an explicitly requested whole-contest admin
task. They do not influence individual Solve readiness.

On “클로드 구조대 준비해라”, the Solve stops immediately and the handoff skill
writes one evidence-backed `rescue/<contest>/<challenge>/HANDOFF.md`. It does not
call Claude, move the original archive, or create another runtime.
