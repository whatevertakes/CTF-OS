# CTF-OS

CTF-OS is a one-challenge, Sol-native first-to-flag environment for authorized
CTFs. It preserves challenge/attempt isolation, read-only inputs, category
sandboxes, declared-target scope, process/GPU resources, manual submission, and
manual Claude handoff.

```text
prepare selected challenge
→ Root Sol xhigh attacks immediately
→ optional 0–3 Sol/Terra/Luna native workers
→ actual commands, artifacts, and attack mutation
→ declared remote
→ first valid target-observed flag
→ sibling cancellation and human submission
```

There is one live Solve engine. The selected challenge owns the machine and
session until a flag, the 90-minute cutoff, or a Claude handoff.

## Setup

```bash
uv sync --frozen
uv run python -m ctf_os.agent_tools doctor
```

Category images are built with `bash sandbox/build-images.sh`.

## Solve flow

Initialize a contest workspace if needed, then prepare only the selected problem:

```bash
uv run python -m ctf_os.agent_tools init-contest 'My CTF 2026'
uv run python -m ctf_os.agent_tools prepare-challenge 'web/Challenge' --contest 'My CTF 2026'
```

Preparation returns direct attack context and zero workers. Root begins its own
attack immediately. When useful, Root creates one optional packet:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-packet 'web/Challenge' \
  --contest 'My CTF 2026' --model-profile terra-high --role builder \
  --context-mode directed --task 'Turn the current request path into remote exploit.py'
```

Profiles are `sol-xhigh` for a new attack mechanism, `terra-high` for an
executable artifact, and `luna-high` for bounded mechanical work. A packet does
not start a model. Root passes its `spawn_agent_args` to native `spawn_agent`
with `fork_turns="none"`, then records the returned identity:

```bash
uv run python -m ctf_os.agent_tools worker-spawn-confirm 'web/Challenge' \
  --contest 'My CTF 2026' --lane terra-1 --native-session '<thread-id>'
```

Only an actual native identity is `RUNNING`; Root plus at most three native
children keeps model concurrency at four. Workers share existing resource and
service foundations while retaining private writable paths.

## Events and replacement

`SWARM.json` holds compact attempt/worker state and `ATTACK_EVENTS.jsonl` holds
post-execution facts. `attack-event` records actual commands, artifacts,
primitives, PoCs, remote results, useful failures, blockers, and candidates.
Execution comes first, so event-write failure cannot block a completed command.

`worker-status` exposes compact real-output history. Root decides whether to keep
or stop a worker and may call `worker-replace` with another profile, role, task,
and fresh or directed context. Python does not score role quality.

After minute 60, `worker-endgame` may replace one qualified worker with
`ctf_sol_max`. Qualification requires an executable partial path, two actual
attack outputs, an exact non-environment reasoning blocker, and a concrete next
attack. The lease is ten minutes or two attacks. The 90-minute cutoff writes
`artifacts/TIMEOUT_HANDOFF.md`, returns cancel targets, and never extends.

## Flag and isolation

A usable payload or meaningful local response is enough to attack the declared
remote. `flag-found` accepts only a format-valid non-placeholder candidate that
appears in actual target output with an exact executed command. It chooses the
first winner and returns native sibling cancel targets. CTF-OS never submits;
`submission-result` records human `wrong` or `accepted` feedback.

- A fresh attempt inherits no artifact, cache, native identity, sandbox, service,
  or solver state.
- Input is read-only; each worker writes only in private `work`, `evidence`, and
  `artifacts` paths.
- Sandboxes enforce organizer-declared target scope and block host/private data.
- Shared service and global resource changes remain Root-only.

Whole-contest Intake and Triage run only when explicitly requested and do not
affect a Solve. On “클로드 구조대 준비해라”, stop the attack and use the handoff
skill to write one evidence-backed `rescue/<contest>/<challenge>/HANDOFF.md`.
