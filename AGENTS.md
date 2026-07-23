# CTF-OS — verified asynchronous portfolio race

`ctf_os/resources/agent-policy.md` is authoritative. For a challenge name,
category/name, numbered problem, deep solve, or parallel request, keep the
current user-opened Root Sol session and activate exactly that challenge.

Prepare it once:

```bash
uv run python -m ctf_os.agent_tools race-prepare '<selector>' --contest '<contest>' \
  --root-model-profile sol-ultra --service-isolation per-lane
```

Preparation must return `attack_ready: true` and a Root sandbox with
`status: READY`. It selects and inspects the category image locally, starts or
attaches the Root-owned challenge service when required, records the actual Root
model profile (default `sol-ultra`), enables per-lane local-service isolation,
and creates the Root sandbox. There is no separate sandbox creation step. If
preparation is not attack-ready, report its exact blocker and recovery command;
never inspect or attack the challenge from the host.

Root is the lead attacker, not a coordinator. Immediately append an actual
attack argv to `next_root_action.exec_command_prefix`. Every analyzer, compiler,
debugger, script, solver, payload, and remote request runs through
`sandbox-exec`. Only controller commands run on the host. `race-bootstrap`
remains blocked until that Root attack produces a durable command receipt.

Root may bootstrap one to three native children in one request. Each lane spec
contains exactly `model_profile`, `role`, `task`, `context_mode`, and a distinct
`attack_family`. Execute only the returned native `SPAWN` actions, pass every
`spawn_agent_args` unchanged to native `spawn_agent`, then record all returned
threads in one `race-reconcile` batch. Python never starts or interrupts native
agents. Fresh lanes receive only challenge, read-only input, targets, shared
verified artifact manifests, and their sandbox; directed lanes may additionally
receive compact verified blackboard delta.

Keep total concurrency at Root plus three. Sol Ultra and Sol max are valid early
independent lanes when worth their cost; Sol xhigh, Terra high, and Luna high
remain the efficient attack, builder, and mechanical profiles. Every attack
completion automatically runs supervision. A live command/session heartbeat
suppresses stagnation, and status polling never creates a stagnation signal.
Stop or replace a lane when supervision returns a native `INTERRUPT` action for
repeated execution/output, unchanged artifacts, duplicate work, expired idle
lease, or a remote-ready primitive without a remote attempt. After interrupting
children, send all results in one `race-reconcile` batch; it removes each private
sandbox and service while preserving private and shared artifacts. Cleanup keeps
the lane in `STOPPING` or `CLEANUP_FAILED`; only `STOPPED` frees its replacement
slot. Retry a controller cleanup failure with
`race-lane-cleanup --lane <lane-id>` before replacement. Share only events
accepted by the append-only blackboard after their command/session receipt
exists. Verified artifacts are immutable and directly readable by every lane
under `/shared-artifacts`.

All sandbox command and persistent-session output is flag-scanned. The first
non-placeholder candidate matching the challenge pattern and observed from the
challenge or a declared target is displayed immediately. Root interrupts every
returned sibling cancel target. A human alone submits flags.

Preserve exact-run identity, read-only input, lane-private writable paths,
declared-target-only egress, aggregate managed-container resource reservation,
per-lane local service networks, cloud metadata denial, no host Docker socket or
personal credential mounts, Root-authorized service lifecycle, and atomic
state/path validation. At the 90-minute deadline terminate without extension,
interrupt native workers, reconcile their stops, then clean the exact run.

“클로드 구조대 준비해라” has priority over new attacks. Load the handoff skill,
terminate the exact race, save one evidence-backed `HANDOFF.md`, interrupt every
returned native cancel target, clean the exact run, and end the Solve.
