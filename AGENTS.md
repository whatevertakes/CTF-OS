# CTF-OS — verified asynchronous portfolio race

`ctf_os/resources/agent-policy.md` is authoritative. For a challenge name,
category/name, numbered problem, deep solve, or parallel request, keep the
current user-opened Root Sol session and activate exactly that challenge.

Prepare it once:

```bash
uv run python -m ctf_os.agent_tools race-prepare '<selector>' --contest '<contest>'
```

Preparation must return `attack_ready: true` and a Root sandbox with
`status: READY`. It selects and inspects the category image locally, starts or
attaches the Root-owned challenge service when required, and creates the Root
sandbox. There is no separate sandbox creation step. If preparation is not
attack-ready, report its exact blocker and recovery command; never inspect or
attack the challenge from the host.

Root is the lead attacker, not a coordinator. Immediately append an actual
attack argv to `next_root_action.exec_command_prefix`. Every analyzer, compiler,
debugger, script, solver, payload, and remote request runs through
`sandbox-exec`. Only controller commands run on the host.

Root may bootstrap zero to three native children in one request. Each lane spec
contains exactly `model_profile`, `role`, `task`, `context_mode`, and a distinct
`attack_family`. Pass every returned `spawn_agent_args` unchanged to native
`spawn_agent`, then record the returned thread with `race-spawn-confirm`. Python
never starts or interrupts native agents. Fresh lanes receive only challenge,
read-only input, targets, and their sandbox; directed lanes may additionally
receive compact verified blackboard delta.

Keep total concurrency at Root plus three. Use Sol xhigh for an independent
attack mechanism, Terra high to finish a verified direction into an executable
artifact, and Luna high for bounded mechanical work. Stop or replace a lane as
soon as `race-status` shows repeated execution/output, no command progress,
unchanged artifacts, duplicate work, or a remote-ready primitive without a
remote attempt. After interrupting a child, call `race-stop-confirm` to remove
its private sandbox while preserving artifacts, then replace it. Share only
events accepted by the append-only blackboard after their command/session
receipt exists.

All sandbox command and persistent-session output is flag-scanned. The first
non-placeholder candidate matching the challenge pattern and observed from the
challenge or a declared target is displayed immediately. Root interrupts every
returned sibling cancel target. A human alone submits flags.

Preserve exact-run identity, read-only input, lane-private writable paths,
declared-target-only egress, cloud metadata denial, no host Docker socket or
personal credential mounts, Root-only shared service lifecycle, and atomic
state/path validation. At the 90-minute deadline terminate without extension,
interrupt native workers, then clean the exact run.

“클로드 구조대 준비해라” has priority over new attacks. Load the handoff skill,
terminate the exact race, save one evidence-backed `HANDOFF.md`, interrupt every
returned native cancel target, clean the exact run, and end the Solve.
