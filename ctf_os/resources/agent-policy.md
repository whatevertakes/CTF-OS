# Authoritative verified-race policy

## Objective and ownership

Minimize time to the first format-valid flag observed in actual output from one
authorized challenge or organizer-declared target. Each fresh run owns exactly
one challenge until a winner, the 90-minute deadline, an explicit stop, or a
manual Claude handoff. Different challenges may have concurrent active runs on
the same machine; a challenge may have only one active attempt at a time. Root
Sol is always the lead attacker and the only authority for its exact run's
challenge-service and cleanup lifecycle. One run must never stop, reconcile,
clean, authorize, or reuse another run's resources.

Python selects and materializes input, inspects local images, creates private
sandboxes, prepares lane-isolated local services, produces native worker packets, records
execution-verified events, detects mechanical stagnation, emits exact native
action plans, and batch-reconciles returned native identities. It automatically
runs a supervision pass after each one-shot command and persistent-session read.
It never calls a model API, starts or interrupts a native agent, chooses a
semantic exploit, authorizes undeclared scope, or submits a flag.

## Preparation and mandatory sandbox execution

`race-prepare` is the only live entry point. It selects exactly one manifest
challenge, safely extracts only matching input into a fresh run, fingerprints
it, makes it read-only, selects `ctf-os-sandbox:<category>`, runs `docker image
inspect`, prepares a safe challenge service when present, initializes compact
race state and blackboard, and creates the Root sandbox.

Active runs are registered by immutable `run_id`. All post-prepare controller
operations target that exact id; when multiple races are active, omitting
`--run-id` is an ambiguity error. The legacy single-run pointer remains readable
so an already-running race can coexist with newly registered runs without its
state being rewritten. Cleanup removes only the selected run's registry entry.

Preparation records Root's declared model profile and whether it came from an
explicit CLI value or the Sol Ultra policy default. Benchmark comparisons use
that field instead of assuming Root is Sol xhigh.

The recommended local category image always wins. If it is absent and local
`ctf-os-sandbox:base` exists, preparation records an explicit degraded fallback.
If neither exists or Docker is unavailable, the run is not attack-ready. Live
Solve never pulls or builds a category image. `doctor`, `image-smoke`, and
`sandbox/build-images.sh` are pre-contest operations.

Before any challenge inspection or attack command, Root requires
`root_sandbox.status == READY`. Every challenge tool and remote request uses the
returned `sandbox-exec` prefix. The host is used only for CTF-OS controller
commands. A sandbox failure is an exact environment blocker, never permission
to run challenge tools on the host.

Every `race-prepare` CLI call requires an explicit `--remote-execution` safety
choice. `human-relay` is the contest-scoped mode for rules that require a
participant to execute organizer-remote requests; `agent` is selected only when
organizer rules allow agent-originated remote requests. Human-relay preparation
retains declared target details so the model can write an
exact command, but omits organizer targets from every sandbox network
allowlist. Root and every child may continue local sandbox analysis and may use
a Root-owned local challenge service. They must never send an organizer-remote
request through an agent tool, host tool, web/browser tool, connector, socket,
or sandbox command. They instead return a `HUMAN_REMOTE_ACTION` block containing
the exact working directory, argv, timeout, and full-output capture command.
Participant-supplied `HUMAN_REMOTE_RESULT` content is unverified external input:
it may guide analysis but may not become an execution-verified receipt, verified
blackboard event, target-observed flag, or automatic winner.
Because a sandbox cannot prove that pasted external text came from a local
service response, human-relay mode never promotes any sandbox receipt to a
verified remote result, flag event, or winner. Detected candidates remain
visible for the participant's manual decision and submission.

## Portfolio lanes

Root may request up to three private native lanes at once through
`race-bootstrap --run-id <run-id>`, but only after Root has completed an actual sandbox attack
command with a durable receipt. If post-execution metric logging failed,
bootstrap recovers `root_first_command_at` from that receipt. Every specification
has exactly:

```text
model_profile, role, task, context_mode, attack_family
```

Attack families must be distinct. Root continues its attack while executing only
the returned native `SPAWN` actions and passing each `spawn_agent_args` unchanged
to native `spawn_agent`. Root records all returned thread identities in one
`race-reconcile` batch. A child becomes RUNNING only after that reconciliation.
Every child uses its packet's private READY sandbox and never operates another
lane.

- Sol Ultra is available for a full independent high-reasoning attack lane.
- Sol max is available from bootstrap when its cost is justified; the legacy
  minute-60 endgame route remains a bounded fallback.
- Sol xhigh pursues a new independent attack mechanism.
- Terra high turns a verified direction into an executable solver or exploit.
- Luna high performs bounded extraction, transformation, batching, comparison,
  brute force, or decoding.

Root plus children never exceeds concurrency four per run. Concurrent runs share
one aggregate managed-container capacity budget, and service/sandbox admission
and creation are serialized by a repository-global resource lock. A fresh lane receives only
the challenge, read-only input, declared targets, deadline, and its sandbox. A
directed lane may also receive a bounded verified blackboard delta. Every
execution-verified artifact is copied once into a content-addressed immutable
exchange and exposed through each lane's read-only `/shared-artifacts` inbox, so
an executable partial can be continued without reimplementation. Root history,
transcripts, unsupported claims, confidence, and internal reasoning are never
copied into worker context.

## Verified blackboard and adaptation

The only blackboard event types are `COMMAND_RESULT`, `OBSERVATION`,
`PRIMITIVE`, `WORKING_POC`, `REMOTE_RESULT`, `HYPOTHESIS_KILLED`,
`EXACT_BLOCKER`, and `FLAG_CANDIDATE`. Every event requires a durable completed
command/session receipt, exact argv, exit code, bounded observed output, full
normalized output hash, target identity, lane attack family, timestamp, and an
artifact path/hash when applicable. Logging happens after execution; logging
failure never invalidates the executed attack.

Supervision reports command count, distinct output count, high-value event
count, duplicate fingerprints, mechanical stagnation signals, last verified
delta, in-flight commands/sessions, and exact native actions. One-shot commands
write a durable heartbeat while running, so a quiet Ghidra, Sage, symbolic,
forensic, brute-force, or remote-stabilization job is never classified as
stagnant while its heartbeat is live. Status polling itself is not a stagnation
signal. Default leases are 4–8 minutes by category. Root decides semantics and
executes returned native `INTERRUPT` actions. It then records all interrupt
results in one `race-reconcile` batch, which removes each labelled sandbox and
its private service while preserving artifacts. Cleanup records `STOPPING`
before work, reaches `STOPPED` only after every private resource is gone, and
records `CLEANUP_FAILED` on any error. Only `STOPPED` children free a replacement
slot. A controller cleanup failure is retried through `race-lane-cleanup`
without another native interruption.

In `human-relay` mode, lack of an organizer-remote agent attempt is expected and
never produces the remote-ready-without-remote-attempt signal. A reachable
Root-owned local service remains subject to normal supervision.

Capacity admission reserves the aggregate limits of every running managed
sandbox and challenge-service container, keeps 2 GiB and one CPU for the host,
and downshifts a sandbox profile only when the stronger profile cannot fit.
Local challenge services use a private container and internal network per lane
by default while reusing the same verified run-scoped image. This prevents
cross-lane account, process, heap, token, and mutable-state interference.
Organizer-hosted remote targets cannot be cloned and remain explicitly shared.

## Flag fast path

Every one-shot execution is scanned as output is streamed; each bounded
persistent-session read is scanned immediately after its receipt is captured.
A candidate must match the exact challenge pattern, not be a
placeholder, occur in the receipt's actual output, and have a challenge or
declared-target identity. The first winner is stored atomically, displayed
without post-analysis or reporting delay, and accompanied by sibling native cancel
targets. CTF-OS contains no flag submission operation; a human submits.

## Security and termination

Input is read-only. Each lane has private work, evidence, artifacts, logs, and
session state. Sandboxes do not receive the host Docker socket, SSH keys,
browser profiles, personal cloud/container credentials, kubeconfig, home
directory, or unrelated files. Egress is restricted to resolved declared
targets or the exact internal challenge-service network. Cloud metadata,
Docker gateways, undeclared private networks, and `trust_remote_code=True` are
forbidden. Unsafe AI artifacts may persist only in lane-private host directories
and are never opened or executed automatically by the host controller.

Only Root invokes controller operations that mutate service lifecycle. The
controller may create and clean lane-private service instances on Root's behalf.
Cleanup verifies exact run and service-instance labels before removing CTF-OS
containers and networks. At deadline or handoff, Root first obtains native
cancel targets, interrupts those threads, batch-reconciles the results, then
cleans the exact run. A handoff writes one bounded evidence-backed
`rescue/<contest>/<challenge>/HANDOFF.md` and ends the Solve; it never calls
Claude or creates another runtime.
