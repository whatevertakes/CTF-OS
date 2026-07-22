---
name: ctf-solve
description: Solve exactly one authorized CTF challenge with the current user-opened Sol session and an immediate native first-to-flag swarm.
---

# CTF Solve — first to flag

Read `ctf_os/resources/agent-policy.md`, root `AGENTS.md`, and only the selected
category playbook. This is a 90-minute timed CTF attack. The current user-opened
session is `/root`, Sol xhigh, lead attacker, remote operator, and flag judge.
Python prepares isolated inputs, sandboxes, packets, events, and artifacts. It
never starts a model, stops a native child, submits a flag, or authorizes an
attack.

If the user requests a Claude handoff, stop before any new attack command, load
the handoff skill, save its single evidence-backed `HANDOFF.md`, and end the
Solve.

## Prepare and immediately spawn

Run the selected challenge's challenge-local preparation in this same session:

```bash
uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'
```

Pass description, hints, flag format, supplied files, and organizer-declared
remote information from the current request through the existing session-input
mechanism, adding `--session-input-json '<bounded challenge-local JSON>'` to that
same prepare command when the request supplies or overrides those fields. Whole-contest Intake, Triage, a Board, tier, evidence grade, and recon
approval are never prerequisites.

Successful preparation returns `spawn_queue` with exactly these initial lanes:

```text
/root/independent
/root/exploit-first
/root/tool-driven
```

Before any additional analysis or recon command, Root must call native
`spawn_agent` once for every initial packet. Pass each packet's
`spawn_agent_args` exactly, including `fork_turns="none"`. Do not translate the
packet into a shell command, Python subprocess, model API call, or JSON plan-only
workflow. The initial three native calls are mandatory even when an extra
capability check would be useful; capability discovery must not delay them.

After all three native calls have been issued, record each returned native
thread/session ID:

```bash
uv run python -m ctf_os.agent_tools swarm-spawn-confirm '<selector>' \
  --contest '<contest>' --lane '<lane>' --native-session '<actual-thread-id>'
```

Only a child with an actual returned native identity is `RUNNING`. If start
fails, call `swarm-spawn-failed`, retry that lane once when the returned packet
allows it, and keep Root attacking regardless. `PENDING_SPAWN` or a packet alone
is not a live swarm.

Immediately after issuing the native starts, create/attach each lane's
category sandbox using its packet metadata. Challenge input is read-only; each
lane writes only under its private `work`, `evidence`, and `artifacts` paths.
Root does not wait for child completion or poll low-value progress. Root begins
its own most promising attack as soon as the native starts are issued.

The native surface in this installation accepts `task_name`, `message`, and
`fork_turns`. If it cannot directly select model/reasoning, use the minimal
`ctf_sol_xhigh` project profile where supported; lack of model attribution never
blocks the live solve. Use `ctf_sol_max` only for the bounded 60-minute endgame
contract below.

## Lane contracts

Every packet contains only challenge-local facts: name, category, description,
hint, flag format, prepared input path, declared remotes, sandbox paths, deadline,
and lane role. It must not contain Root's private reasoning.

`independent` receives no Root hypotheses and independently races for the
shortest flag path.

`exploit-first` obeys:

```text
Do not produce a report.
Do not seek complete understanding.
Find, build, and run the smallest plausible exploit.
```

`tool-driven` obeys:

```text
Your progress must be commands, scripts, payloads,
runtime observations, or exact blockers from actual execution.
```

All lanes immediately use tools and follow one loop:

```text
MINIMAL OBSERVATION
→ ONE ATTACK PATH
→ SMALLEST EXECUTABLE ATTACK
→ RUN
→ READ REAL OUTPUT
→ MUTATE OR REPLACE
→ REMOTE
→ FLAG
```

Do not wait for complete understanding, enumerate the whole attack surface,
write a report first, build a reusable framework, or refactor a PoC before a
remote attempt.

## Attack and remote fast path

Runtime attack state is only:

```text
ATTACK_PATH_FOUND
EXPLOIT_ATTEMPTED
USEFUL_FAILURE
FLAG_FOUND
```

These are post-execution records, never permissions. A crash, leak, oracle,
bypass, read/write path, controlled code path, solver-linked reduction,
decrypt/extract candidate, or constructible remote request is an attack path.
Within the next two meaningful tool actions, execute a payload, PoC, solver, or
remote attack. Do not require a separate control experiment.

If a remote is declared, check reachability early. After one meaningful local
response or a payload that can be sent, go remote immediately. Do not delay for
a clean replay, edge cases, PoC approval, or any authorization receipt. Preserve
only the exact command, bounded output, and exploit artifact after execution.
If event append fails, retain the command output locally and continue attacking;
recording failure never blocks execution.

Record compact events with `attack-event`. Share with siblings only:

```text
PRIMITIVE
WORKING_POC
REMOTE_RESULT
FLAG_FOUND
BLOCKER
USEFUL_FAILURE
```

Root checks sibling state only at those events or child termination. Do not
share general source summaries, long decompilation, unexecuted hypothesis lists,
file listings, or “still analyzing” updates.

## Failure, replacement, and time

After a failed attack, change one variable and rerun, apply a sibling result and
rerun, or switch to a fresh attack family. Never repeat an identical failing
command without a changed input or reason.

At 30 minutes, call `swarm-status`. Replace at most two low-yield running lanes
that have no primitive/PoC and are repeating one family or analysis. Native-stop
the chosen child first, then call `swarm-replace` with the exact failed command,
stdout/stderr or remote response, disproved path, exact blocker, and untried
family. There is no lifetime one-replacement limit; only the 90-minute deadline,
native concurrency four including Root, and non-repetition apply.

At 60 minutes, `swarm-status` may identify one Max endgame candidate only when a
partial executable path exists, at least two actual attacks ran, and a concrete
reasoning blocker remains. Its `ctf_sol_max` lease is ten minutes or two actual
attacks, whichever comes first. Environment, dependency, Docker, target-down,
rate-limit, and ordinary tool failures never justify Max.
Stop that candidate's current native lane and call `swarm-endgame` with its exact
native session; then issue the returned native max packet and confirm its actual
thread ID like any other spawn.

At 90 minutes, call `swarm-status`, interrupt every returned cancel target, and
stop. Do not extend automatically. Preserve only the leading attack path, actual
exploit/script, exact commands and output, observed primitive, exact blocker,
and one next attack in `artifacts/TIMEOUT_HANDOFF.md`. A user request to continue
starts a fresh 90-minute attempt generation.

## First flag wins

Any lane sends a flag candidate to Root immediately with its exact command and
actual target output. Root checks only that the challenge format matches, the
candidate appears in actual output, and it is not a placeholder. Then call:

```bash
uv run python -m ctf_os.agent_tools flag-found '<selector>' \
  --contest '<contest>' --lane '<lane>' --candidate '<flag>' \
  --observed-output '<actual-output>' --artifact '<run-relative-artifact>' \
  --source '<target/source>' -- '<exact-command>'
```

Display the returned block immediately:

```text
REMOTE FLAG OBTAINED
Challenge: <challenge>
Flag: <flag>
Source: <lane / command>
Recommendation: submit immediately
```

Immediately call native `interrupt_agent` for every returned cancel target,
record each with `swarm-stop-confirm`, and do no additional analysis or replay.
The human submits; automatic submission is forbidden.

If the human reports `WRONG`, record that exact candidate with
`submission-result`; discard only it and immediately spawn the returned fresh
striker packet. If the human reports `ACCEPTED`, record it, stop remaining native
children, and clean only CTF-OS-owned sandboxes/resources.

Attack exactly one selected challenge and only organizer-declared targets.
Never access cloud metadata, Docker gateways, unrelated LANs/challenges, host
Docker socket/root, SSH keys, browser profiles, personal credentials, or personal
files. A child mutates only its own private service; Root alone owns shared
service, global resources, native lifecycle, remote judgment, and submission
feedback.
