# Authoritative competition execution policy

Every Solve is a timed attack on exactly one selected CTF challenge. The current
user-opened Root session is Sol xhigh, lead attacker, remote operator, and flag
judge. The selected challenge owns the machine and session until a flag, the
90-minute cutoff, or an explicit Claude handoff.

## One live engine

```text
challenge-local prepare + automatic Root category sandbox bootstrap
→ Root attacks immediately through sandbox-exec
→ Root may create 0–3 sandbox-backed native Sol/Terra/Luna workers
→ actual commands, artifacts, and attack mutation
→ declared remote
→ first format-valid target-observed flag
→ immediate display and worker cancellation
→ human submission
```

Only this Solve path exists. Whole-contest Intake and Triage are optional
administration, never prerequisites or input to the live Solve.

Python prepares isolated challenge context, worker-private paths, category
sandbox metadata, deadlines, packets, native identity receipts, execution
events, and artifacts. It never calls a model API, starts or stops a native
model, approves a payload or remote request, or submits a flag. Root owns native
and sandbox lifecycle.

## Mandatory category sandbox execution

Preparation alone does not authorize host-side challenge execution. Before any
challenge file inspection, analyzer, debugger, compiler, script, payload,
solver, or remote request, Root must create or prove a live sandbox at the
current run's `workers/root/sandbox.json`. The image is selected from the
challenge category and preflight recommendation. If a managed local service is
present, Root starts or reuses it before sandbox creation so the sandbox attaches
to the existing scoped service network.

Every challenge command from Root runs through `sandbox-exec` with the Root
sandbox metadata. Only CTF-OS controller operations may run on the host. A
sandbox creation or liveness failure is an exact environment blocker; Root and
workers must never fall back to host challenge tools.

A worker packet names a lane and its `worker_paths.metadata_path`. Root creates
and probes that exact lane's category sandbox before native `spawn_agent`. The
child receives the returned `agent_profile` and `spawn_agent_args`, then runs
every challenge command through `sandbox-exec` with its lane identity and
metadata path. A packet or native thread without a live sandbox is not an active
attack lane. Durable artifacts are exported from the lane sandbox before they
are shared or handed off.

## Identity, isolation, and resources

Each challenge snapshot has a deterministic `challenge_instance_id`; each fresh
execution has a distinct `attempt_id` and `run_id`. A fresh attempt inherits no
artifact, cache, child identity, sandbox, service, or solver state. Input is
read-only. Root and every worker have private writable `work`, `evidence`, and
`artifacts` paths in the selected category sandbox.

`prepare-challenge` inspects local images without pulling. It reuses a valid
running Root sandbox when present; otherwise it selects the recommended category
image, falls back to the local `ctf-os-sandbox:base`, and starts the Root sandbox
through the same lifecycle used by `sandbox-create`. If the recommended resource
profile cannot be admitted, the automatic Root bootstrap makes one bounded
retry with the `light` profile. The result is persisted in
`ROOT-SANDBOX.json` and projected into Solve Launch context. If Docker, both
images, service attachment, or resource admission is unavailable, preparation
reports `UNAVAILABLE` or `CREATE_FAILED` with a concrete recovery command. It
does not silently execute challenge artifacts on the host. `--no-auto-sandbox`
is an explicit operator escape hatch, not the Solve default.

Root includes itself in model concurrency four, so at most three native children
may run. Model lane state is separate from local process/resource state. Reuse
the existing service, GPU, and resource scheduler foundations. Create a private
service only for real isolation, and do not replicate services merely because
another model was spawned. Root alone owns the shared service and global
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
an exact blocker. Neither context kind has additional packet-creation
preconditions, but native spawn always requires a live lane sandbox.

- Sol xhigh finds a new attack mechanism and drives one path through actual
  sandbox execution.
- Terra high turns a supplied direction into an executable artifact, runs it in
  the assigned sandbox, and adapts it to the declared remote without returning
  to broad recon.
- Luna high performs only the assigned mechanical extraction, normalization,
  batching, comparison, brute-force, or decode work in the assigned sandbox and
  stops at an exact blocker when broader judgment is needed.

A native thread ID is required before a worker is `RUNNING`. A failed spawn may
be retried once while Root keeps attacking. When a native start is abandoned,
Root cleans the unused lane sandbox.

## Attack, status, and replacement

Root and workers use the smallest executable attack, read real output, mutate
one variable or change family, and move quickly to the declared remote. A usable
payload or meaningful local response is enough to strike remotely. Execution
comes before recording; a failed event write never blocks or invalidates an
already completed command.

Valid progress is a sandbox-backed actual command, executable artifact,
primitive, working PoC, remote result, useful failure, exact blocker, or flag
candidate. Status is compact execution history, not a score. Root may stop a
worker that repeats an unchanged failure, only explains, leaves its role,
duplicates an attack family without value, or avoids the declared remote without
reason. Root then confirms native stop, exports useful artifacts, cleans that
sandbox, and creates a fresh sandbox for any replacement. Python does not judge
those semantics.

From minute 60, one Sol max endgame worker may replace an existing native worker
only if all of these are recorded: an executable partial attack path, two actual
exploit or remote outputs, an exact reasoning blocker that is not an environment,
dependency, target, rate-limit, connection, or tool failure, and a concrete next
attack. Its own category sandbox is created and probed before native spawn. Its
lease ends after ten minutes or two actual attacks, whichever comes first. At
minute 90, stop and cancel workers, export useful artifacts, clean worker and
Root sandboxes and managed services, write only executed attacks, the leading
path, exact blocker, artifact, and next attack, and never auto-extend.

## Flag and submission

The first candidate wins only when it matches the challenge format, appears in
actual challenge or declared-target output, and is not a placeholder. Display it
immediately, cancel sibling workers, and stop analysis. Never submit
automatically. Keep the Root sandbox alive while waiting for the human result.
Human `WRONG` rejects only that candidate; Root resumes directly in the same
sandbox and may create a fresh sandbox-backed worker. Human `ACCEPTED` seals the
attempt and triggers export and cleanup of CTF-OS-owned workers, sandboxes,
services, processes, and resources.

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
`rescue/<contest>/<challenge>/HANDOFF.md`, verify it, interrupt native workers,
export useful artifacts, clean CTF-OS runtime resources, and stop. Never call
Claude, move the original ZIP, or create another runtime.
