# Solve-rate-first solver design

This policy optimizes valid-flag solve rate, not prose quality, evidence volume,
or model cost. Safety and candidate verification remain hard constraints.

## Persistent solve session

Every queued challenge has one durable `ChallengeSession`. Sol owns that
session across planning generations, resumes the same Codex thread, issues
strict `ExecutionContract` branches, synthesizes their handoffs, and decides
what must run next. A completed recon or failed exploit ends only its branch;
it does not end the challenge session.

```text
ChallengeSession (Sol max, persistent)
├─ Luna: narrow reconnaissance and branch-selecting tool checks
├─ Terra: concrete exploit, decoder, solver, and independent reproduction
├─ Sol: hard conceptual branch or stalled-branch takeover
└─ Sol: synthesis, replanning, replay review, and termination decision
```

Each contract states its exclusive scope, first decisive action, success
condition, stop condition, required deliverables, and failure handoff. It also
contains a complete `BranchExecutionSpec`: child-session role, authorized model
profile, reasoning effort, prompt family, tool strategy, timeout, and scheduler
priority. The scheduler persists both the session and every contract task in
local SQLite.

## Model roles

- **Sol** owns the problem, creates/replaces contracts, resolves hard forks,
  takes over stalled work, and performs final synthesis.
- **Terra** implements a concrete attack branch and leaves a runnable artifact
  plus exact replay instructions.
- **Luna** answers a narrow uncertainty quickly. It is not the primary owner of
  an unscored challenge.

These are child Codex sessions, not native subagents. Sol may assign the same
job to Luna, Terra, or Sol depending on the current evidence. For example, an
exploit role can start as a short Terra session and later be reissued as a Sol
max takeover without changing the problem's persistent owner.

## Solver algorithm

`CategoryPlanner` output is the scheduler input. `RacePlan.from_solve_plan`
turns the plan into branch attempts; the score-only race is a compatibility
fallback, not the normal production path. Missing scores are never treated as
easy: pwn, rev, and crypto start at hard/Sol ownership, while other categories
start at least medium.

For a clear route Sol should issue one short direct session. For an uncertain
or difficult challenge it may concentrate up to four disjoint high/max
sessions on the core attack surface. `model-routing.yaml` is an operator
allowlist and fallback boundary; it no longer silently replaces a Sol-issued
contract with a static role route. The selected execution timeout and priority
are used by the actual backend call and scheduler queue.

Workers keep isolated `/work` directories. The controller promotes bounded
records and approved `exploit.py`, `solver.py`, `replay.sh`, or `writeup.md`
snapshots into a challenge handoff area and seeds later branches from that
area. Raw flag-shaped output is only an observation; it does not change the
challenge lifecycle. Replay evidence and controller approval are required for
a solved decision.

## Validation policy

Solver quality is evaluated during authorized real CTF operation. Repository
checks cover parser, state migration, scheduling, handoff, routing, sandbox,
and mock/integration behavior only. CTF-OS does not run a synthetic benchmark
suite or use benchmark scores to retune model routing.
