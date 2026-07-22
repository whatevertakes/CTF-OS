# CTF-OS — one-challenge native worker contract

`ctf_os/resources/agent-policy.md` is authoritative. `.codex/skills/ctf-solve/SKILL.md`
defines the one Solve procedure; a selected category playbook supplies bounded
tactics only.

For a challenge name, category/name, numbered problem, deep solve, or swarm
request, keep the current user-opened Root Sol session and prepare only that
challenge. The selected challenge owns the machine and Solve session until a
flag, the 90-minute cutoff, or an explicit Claude handoff. Whole-contest Intake
and Triage are optional admin commands and never Solve prerequisites.

Root is Sol xhigh and the lead attacker, never coordinator-only. Preparation
returns challenge context and no mandatory child lineup. Before any challenge
inspection or attack command, Root creates or proves a live `root` sandbox using
the selected category image. Every analyzer, debugger, compiler, script,
payload, solver, and remote request runs through `sandbox-exec`; host execution
is limited to CTF-OS controller commands. A missing or broken sandbox is an exact
blocker, never permission to fall back to host challenge tools.

Root may at any time prepare zero to three native workers by providing only
`model_profile`, `role`, `task`, and `context_mode`. Use fresh Sol for a new
attack mechanism, Terra high to build a concrete attack, and Luna high for
bounded mechanical work. After packet creation and before native `spawn_agent`,
Root creates and probes the returned lane's category sandbox. Call native
`spawn_agent` with the returned `agent_profile`, `spawn_agent_args`, and
`fork_turns=none`; confirm only the returned thread ID as running. Every child
uses its packet's `worker_paths.metadata_path` and lane identity for
`sandbox-exec`. Python never starts or stops models or submits flags.

Keep a worker only while its sandbox-backed output contains an actual command,
executable artifact, primitive, working PoC, remote result, useful failure,
exact blocker, or flag candidate. Root owns native stop, artifact export, and
sandbox cleanup and may replace an unproductive worker with any general profile
or role. A replacement receives a fresh lane sandbox before native spawn. Sol
max is not a general child: after minute 60 it may replace one worker only when
an executable partial path, two actual attack outputs, an exact non-environment
reasoning blocker, and a concrete next attack all exist. Its lease is ten
minutes or two actual attacks.

Use only organizer-declared targets. Preserve challenge/attempt isolation,
read-only input, worker-private work/evidence/artifacts, category sandboxes, and
real process/GPU resource management. Never access the host Docker socket, SSH
keys, browser profiles, personal cloud credentials, cloud metadata, or
undeclared private networks. Do not auto-submit a flag.

Execution precedes event recording; a log failure never invalidates a completed
attack. Send a usable payload to the declared remote without approval gates.
The first format-valid candidate observed in actual target output is displayed
immediately; Root cancels every sibling and a human submits. Keep the Root
sandbox for `WRONG`; on `ACCEPTED`, timeout, or handoff, export needed artifacts
and clean CTF-OS-owned sandboxes, services, processes, and resources. At 90
minutes stop without extension and preserve the compact timeout handoff.

“클로드 구조대 준비해라” has priority over every new attack. Load the handoff
skill, write the single evidence-backed `HANDOFF.md`, terminate native workers,
clean CTF-OS runtime resources, and end that Solve.
