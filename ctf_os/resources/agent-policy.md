# Authoritative verified-race policy

## Objective and ownership

Minimize time to the first format-valid flag observed in actual output from one
authorized challenge or organizer-declared target. One fresh run owns the
machine until a winner, the 90-minute deadline, an explicit stop, or a manual
Claude handoff. Root Sol is always the lead attacker and the only owner of
shared service and global cleanup lifecycle.

Python selects and materializes input, inspects local images, creates private
sandboxes, prepares the shared service, produces native worker packets, records
execution-verified events, detects mechanical stagnation, and returns native
cancel targets. It never calls a model API, starts or interrupts a native agent,
chooses a semantic exploit, authorizes undeclared scope, or submits a flag.

## Preparation and mandatory sandbox execution

`race-prepare` is the only live entry point. It selects exactly one manifest
challenge, safely extracts only matching input into a fresh run, fingerprints
it, makes it read-only, selects `ctf-os-sandbox:<category>`, runs `docker image
inspect`, prepares a safe challenge service when present, initializes compact
race state and blackboard, and creates the Root sandbox.

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

## Portfolio lanes

Root may request up to three private native lanes at once through
`race-bootstrap`. Every specification has exactly:

```text
model_profile, role, task, context_mode, attack_family
```

Attack families must be distinct. Root continues its attack while passing each
returned `spawn_agent_args` unchanged to native `spawn_agent`. A child becomes
RUNNING only after Root records the actual native thread identity. Every child
uses its packet's private READY sandbox and never operates another lane.

- Sol xhigh pursues a new independent attack mechanism.
- Terra high turns a verified direction into an executable solver or exploit.
- Luna high performs bounded extraction, transformation, batching, comparison,
  brute force, or decoding.
- Sol max is not a routine lane; it may be introduced only after minute 60 for
  an executable partial path, two actual attack outputs, an exact non-environment
  reasoning blocker, and one concrete next attack. Its lease is ten minutes or
  two actual attacks.

Root plus children never exceeds concurrency four. A fresh lane receives only
the challenge, read-only input, declared targets, deadline, and its sandbox. A
directed lane may also receive a bounded verified blackboard delta. Root history,
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

`race-status` reports command count, distinct output count, high-value event
count, duplicate fingerprints, mechanical stagnation signals, last verified
delta, and replaceable native cancel targets. Default leases are 3–8 minutes by
category. Root decides semantics and rapidly stops or replaces repeated,
stagnant, or remote-avoiding lanes. After Root interrupts a native child,
`race-stop-confirm` immediately removes that child's labelled sandbox while
preserving its private host-side artifacts, so replacement never accumulates
inactive containers.

## Flag fast path

Every one-shot execution and persistent-session read is scanned as output is
processed. A candidate must match the exact challenge pattern, not be a
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
forbidden. Unsafe AI artifacts remain inside the sandbox.

Only Root mutates shared service lifecycle. Cleanup verifies exact run labels
before removing CTF-OS containers and networks. At deadline or handoff, Root
first obtains native cancel targets, interrupts those threads, then cleans the
exact run. A handoff writes one bounded evidence-backed
`rescue/<contest>/<challenge>/HANDOFF.md` and ends the Solve; it never calls
Claude or creates another runtime.
