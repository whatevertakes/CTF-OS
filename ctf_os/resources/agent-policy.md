# Authoritative competition execution policy

This policy governs every Solve. It is a timed CTF attack, not vulnerability
research, a comprehensive assessment, or a benchmark. The only objective is the
first valid flag. Prefer an executable exploit path over analysis breadth,
documentation, reusable architecture, clean replay, or token savings.

## One live engine

Every selected challenge uses the same engine:

```text
challenge-local prepare
→ immediate Root + three native Sol lanes
→ actual commands and exploit mutation
→ declared remote
→ first format-valid target-observed flag
→ immediate display and lane cancellation
```

The current user-opened `/root` session is Sol xhigh and remains lead attacker.
It is never coordinator-only: after issuing the three initial native starts it
keeps attacking its best path without waiting. Initial children are independent,
exploit-first, and tool-driven, use `fork_turns=none`, receive no Root reasoning,
and are not `RUNNING` without an actual native thread/session ID.

Python may prepare isolated inputs, worker paths, sandbox specifications, native
packets, execution events, deadline state, and artifacts. Python never starts or
stops a model, supervises native lifecycle, calls a model API, approves an
exploit/remote action, or submits a flag. A spawn failure is recorded and may be
retried once while Root continues attacking.

## Identity and preserved foundations

Preparation uses only the current request and selected challenge. Description,
hint, flag format, supplied files, and organizer-declared remote data are carried
through the same user-opened session. Whole-contest Intake, Triage, rankings,
difficulty, or a Board are optional administration and never Solve prerequisites.

Each challenge snapshot has deterministic `challenge_instance_id`; every fresh
execution has its own `attempt_id` and bound `run_id`. A fresh attempt inherits no
artifacts, state, cache, child identity, sandbox, service, or solver files. A
sibling challenge change never stales the selected workspace.

Challenge input is read-only. Each lane receives private writable `work`,
`evidence`, and `artifacts` paths in a category sandbox. GPU and real process/
resource management remain available for actual long compute. A child mutates
only its branch-private service; Root alone owns the shared service, global
resource changes, native lifecycle, remote judgment, and flag feedback.

## Attack loop

Every lane repeats:

```text
MINIMAL OBSERVATION → ONE ATTACK PATH → SMALLEST EXECUTABLE ATTACK
→ RUN → READ REAL OUTPUT → MUTATE OR REPLACE → REMOTE → FLAG
```

An attackable crash, leak, oracle, bypass, read/write, controlled code path,
solver reduction, deterministic extraction/decryption, or sendable remote request
is enough to strike. Execute a payload, PoC, solver, or remote attack within the
next two meaningful tool actions. Real exploit output is the validation. No
separate positive/negative control, approval milestone, or authorization receipt
is required.

Check declared remote reachability early. One meaningful local response or a
sendable payload is enough to go remote. Do not wait for perfect replay, edge
cases, refactoring, or clean exploit code. Execution comes before recording; a
failed event/log write never cancels or precludes an attack.

Share only a primitive, working PoC, remote result, flag candidate, useful
failure, or exact blocker. General summaries, broad recon, unexecuted hypothesis
lists, and “still analyzing” reports are not progress.

## Time and replacement

The default budget is 90 minutes. It promises either a flag or a compact record
of executed attacks and the exact blocker, not guaranteed success.

- 0–5 minutes: prepare, issue all three native spawns, create sandboxes, and use
  tools on every lane.
- 5–30 minutes: independently attack; exploit and go remote as soon as possible.
- 30 minutes: replace up to two low-yield lanes with alternate-family or
  failure-analysis work. Stop the native child before replacement so concurrency
  never exceeds Root plus three. There is no lifetime replacement-count limit.
- 60 minutes: one Sol max lane may receive an executable partial path, at least
  two actual attack outputs, and one concrete reasoning blocker. Lease: ten
  minutes or two attacks. Environment/tool/target/rate-limit failures do not
  qualify.
- 90 minutes: stop, cancel children, and write only leading path, actual script,
  exact commands/output, observed primitive, exact blocker, and one next attack.
  Never auto-extend. A human continuation starts a fresh 90-minute attempt.

After a failed attack, change one variable, apply sibling output, or switch attack
family. Do not repeat the same failed command without a material change.

## First flag and submission

The first candidate from the actual challenge or declared remote wins when it
matches the flag format, appears in actual target output, and is not an obvious
placeholder. Print it immediately, cancel every other native lane, and stop
analysis. Clean replay is optional and must not delay display. Preserve only the
exact command and minimal exploit artifact.

Never submit a flag automatically. Human `WRONG` refutes only that candidate and
immediately resumes the strongest path or a fresh striker. Human `ACCEPTED` seals
the attempt and triggers cleanup of CTF-OS-owned children, sandboxes, services,
processes, and resources.

## Scope and safety

Attack exactly one selected challenge and only organizer-declared targets.
Declared public/private/VPN/IPv6 and supported custom protocols are valid. Cloud
metadata, Docker gateways, undeclared private LANs, other challenges, unrelated
hosts, ambient/personal accounts, and host credentials are forbidden. Never
mount or inspect the host Docker socket/root, SSH keys, browser profiles, personal
cloud credentials/kubeconfig, or personal files. Challenge temporary credentials
and required cloud mutations are allowed only inside declared scope, worker-
private, logged, and redacted. Unsafe AI artifacts remain sandboxed and
`trust_remote_code=True` is forbidden.

“클로드 구조대 준비해라” and equivalent requests terminate the Solve before any
new command. Write only evidence-backed facts and executed history to the single
repository-local `rescue/<contest>/<challenge>/HANDOFF.md`, verify it, then stop.
Never call Claude, move the original ZIP, or create another runtime/workspace.
