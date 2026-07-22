# Authoritative competition execution policy

Every Solve is a timed attack on exactly one selected CTF challenge. The current
user-opened Root session is Sol xhigh, lead attacker, remote operator, and flag
judge. The selected challenge owns the machine and session until a flag, the
90-minute cutoff, or an explicit Claude handoff.

## One live engine

```text
challenge-local prepare
→ Root attacks immediately
→ Root may spawn 0–3 native Sol/Terra/Luna workers
→ actual commands, artifacts, and attack mutation
→ declared remote
→ first format-valid target-observed flag
→ immediate display and worker cancellation
→ human submission
```

Only this Solve path exists. Whole-contest Intake and Triage are optional administration, never
prerequisites or input to the live Solve.

Python prepares isolated challenge context, worker-private paths, sandbox
metadata, deadlines, packets, native identity receipts, execution events, and
artifacts. It never calls a model API, starts or stops a native model, approves a
payload or remote request, or submits a flag. Root owns native lifecycle.

## Identity, isolation, and resources

Each challenge snapshot has a deterministic `challenge_instance_id`; each fresh
execution has a distinct `attempt_id` and `run_id`. A fresh attempt inherits no
artifact, cache, child identity, sandbox, service, or solver state. Input is
read-only. Every worker has private writable `work`, `evidence`, and `artifacts`
paths in the selected category sandbox.

Root includes itself in model concurrency four, so at most three native children
may run. Model lane state is separate from local process/resource state. Reuse
the existing sandbox, service, GPU, and resource scheduler foundations. Create a
private service only for real isolation, and do not replicate services merely
because another model was spawned. Root alone owns the shared service and global
resource changes.

## Optional workers

Root may create a packet whenever it can state only:

```text
model_profile
role
task
context_mode
```

`fresh` contains only the selected problem, prepared input, and declared remote;
it carries no Root facts or failure context. `directed` may additionally carry
bounded confirmed facts, an actual failed command and output, one artifact, and
an exact blocker. Neither context kind has additional creation preconditions.

- Sol xhigh finds a new attack mechanism and drives one path through actual
  execution.
- Terra high turns a supplied direction into an executable artifact, runs it,
  and adapts it to the declared remote without returning to broad recon.
- Luna high performs only the assigned mechanical extraction, normalization,
  batching, comparison, brute-force, or decode work and stops at an exact
  blocker when broader judgment is needed.

A native thread ID is required before a worker is `RUNNING`. A failed spawn may
be retried once while Root keeps attacking.

## Attack, status, and replacement

Root and workers use the smallest executable attack, read real output, mutate
one variable or change family, and move quickly to the declared remote. A usable
payload or meaningful local response is enough to strike remotely. Execution
comes before recording; a failed event write never blocks or invalidates an
already completed command.

Valid progress is an actual command, executable artifact, primitive, working
PoC, remote result, useful failure, exact blocker, or flag candidate. Status is
compact execution history, not a score. Root may stop or replace a worker that
repeats an unchanged failure, only explains, leaves its role, duplicates an
attack family without value, or avoids the declared remote without reason.
Python does not judge those semantics.

From minute 60, one Sol max endgame worker may replace an existing native worker
only if all of these are recorded: an executable partial attack path, two actual
exploit or remote outputs, an exact reasoning blocker that is not an environment,
dependency, target, rate-limit, connection, or tool failure, and a concrete next
attack. Its lease ends after ten minutes or two actual attacks, whichever comes
first. At minute 90, stop and cancel workers, write only executed attacks, the
leading path, exact blocker, artifact, and next attack, and never auto-extend.

## Flag and submission

The first candidate wins only when it matches the challenge format, appears in
actual challenge or declared-target output, and is not a placeholder. Display it
immediately, cancel sibling workers, and stop analysis. Never submit
automatically. Human `WRONG` rejects only that candidate; Root resumes directly
and may freely create a fresh worker. Human `ACCEPTED` seals the attempt and
triggers cleanup of CTF-OS-owned workers, sandboxes, services, processes, and
resources.

## Scope and handoff

Attack only the selected challenge and organizer-declared targets. Cloud
metadata, Docker gateways, undeclared private LANs, other challenges, unrelated
hosts, ambient accounts, host Docker socket/root, SSH keys, browser profiles,
personal credentials/kubeconfig, and personal files are forbidden. Challenge
temporary credentials are allowed only inside declared scope, worker-private,
logged, and redacted. Unsafe AI artifacts remain sandboxed and
`trust_remote_code=True` is forbidden.

“클로드 구조대 준비해라” and equivalent requests terminate the Solve before any
new attack. Write one evidence-backed repository-local
`rescue/<contest>/<challenge>/HANDOFF.md`, verify it, and stop. Never call Claude,
move the original ZIP, or create another runtime.
