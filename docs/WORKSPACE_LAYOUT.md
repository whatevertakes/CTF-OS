# CTF Workspace Layout Contract

This document defines the permanent layout contract for the repository root
containing `AGENTS.md`.

## Root Workspace Role

The workspace root is for framework files only. It should contain workspace
policy, helpers, templates, routing contracts, capability metadata, benchmarks,
and documentation.

Standard root entries:

```text
AGENTS.md
.codex/
tools/
templates/
skills/
capabilities/
benchmarks/
docs/
challenges/
```

Root `tools/` contains workspace-level helpers only. Do not put
challenge-specific exploit scripts, solve scripts, payload generators, or
one-off analysis helpers in root `tools/`.

## Challenge Workspace Role

All CTF problem work lives under:

```text
challenges/<event>/<category>/<challenge>/
```

The workspace should not create separate root workspaces per event or per
challenge.

Blindtest category slots are tracked on main:

```text
challenges/blindtest/<category>/
```

Concrete blindtest challenge workspaces may commit solve outputs such as
`state.json`, `notes.md`, `replay.sh`, and `evidence/`. Raw handouts and
provided problem files under `dist/` remain local-only. Sanitized benchmark
records live under `benchmarks/`.

## Standard Challenge Layout

Every challenge workspace should use this structure:

```text
challenges/<event>/<category>/<challenge>/
  state.json
  notes.md
  replay.sh
  evidence/
  dist/
  work/
```

## Directory Meanings

- `state.json`: machine-readable status, `final_command`, `blocker.reason`,
  `blocker.next_action`, evidence paths, proof scope, remote status, replay
  kind, remote liveness, evidence sensitivity, replay quality, shareability,
  agent mode, failure class, tool effectiveness, tool routing decisions, and
  replay metadata.
- `notes.md`: human-readable solve log, including standard `##` sections for
  summary, artifacts, observations, hypotheses, attempts, tool routing, agent
  design metadata, blocker or solve, and evidence.
- `replay.sh`: reproducible proof or replay entrypoint.
- `evidence/`: replay logs, redacted replay summaries, screenshots, and final
  proof outputs.
- `dist/`: original challenge handouts, binaries, `docker-compose`, and
  provided files.
- `work/`: scratch scripts, exploit drafts, extracted files, and local
  analysis. Level 3 board files, Level 4 interface files, and Level 5
  sanitized automation reports also live here.

## Naming Rules

- Real events use `<yyyy>-<event>`, for example `2026-codegate-quals`.
- Practice events use `practice-<source>`, for example `practice-dreamhack`.
- Framework tests use `_selftest` only.
- Slugs should be lowercase, hyphen-separated, and contain no spaces.

## Standard Categories

Use these category slugs:

```text
pwn
web
rev
crypto
forensics
misc
jail
osint
mobile
malware
web3
cloud
container
ai-ml
hardware-rf
side-channel
hybrid
```

## Workflow Contract

- Create every challenge with `tools/intake_challenge.py`.
- Store original challenge files in `dist/`.
- Store scratch scripts and exploit drafts in `work/`.
- Store durable proof outputs in `evidence/`.
- A solved challenge requires `state.json` with `status` set to `solved`, a
  non-empty `final_command`, replay evidence, a non-`none` proof scope, and a
  passing `proof_validate` result.
- A blocked challenge requires a real non-empty textual blocker reason.
- A partial challenge should preserve evidence or a blocker reason explaining
  why it is not yet solved.
- Record tool routing decisions in `state.json` and `notes.md` for
  observability. This records MCP and non-MCP tool selection, non-selection, and
  missing dependencies; it must not be used to force MCP usage.
- Record agent-design metadata for every solved, blocked, or partial challenge.
  `metadata.agent_mode`, `metadata.failure_class`, `metadata.replay_quality`,
  `metadata.shareability`, and `metadata.tool_effectiveness` are required for
  data-submission validation.
- Raw replay logs that contain flag-like markers must have a matching redacted
  `*.summary.md` file before proof validation succeeds.
- Shared benchmark data may omit raw `evidence/replay_*.log` files when the
  matching `evidence/replay_*.summary.md` exists; the summary is the shareable
  proof artifact.
- Live remote exploit replays should set `metadata.replay_kind` to
  `remote_live` or `remote_live_exploit`; `replay_runner.py` will then require
  explicit `--allow-remote-live` opt-in.
- Level 4 interface views are generated with `tools/level4_interface.py`; they
  may add `metadata.level4_*` pointers but must not replace proof validation or
  create a separate solve status.
- Level 5 automation may run preflight, replay, proof validation, report
  sanitization, and temporary artifact cleanup. It must not mark challenges
  solved, add solvers, or use `challenges/_selftest` as benchmark input.

## Challenge Data Contract

New challenge workspaces are created from `templates/challenge/`. Terminal
states (`solved`, `blocked`, or `partial`) must preserve the current template
shape before being shared as benchmark data.

`state.json.blocker` must be an object:

```json
{
  "reason": "",
  "next_action": ""
}
```

`state.json.metadata` must include:

```text
proof_scope
remote_status
remote_solve
replay_kind
current_remote_liveness
evidence_sensitivity
last_replay
agent_mode
failure_class
replay_quality
shareability
tool_effectiveness
```

Allowed `agent_mode` values are `none`, `assisted`, `autonomous`,
`hermes_readonly`, `lazycodex_readonly`, and `gajae_bounded`. Ordinary
Codex-assisted solving uses `assisted`. Solved challenges must set
`failure_class` to `none`; blocked and partial challenges use the narrowest
label supported by `docs/FAILURE_TAXONOMY.md`.

`notes.md` must use these headings exactly:

```text
## Summary
## Artifacts
## Observations
## Hypotheses
## Attempts
## Tool Routing Decision
## Agent Design Metadata
## Blocker or Solve
## Evidence
```

## Git Policy

- Do not commit secrets, flags, tokens, huge dumps, core files, or private keys.
- `main` tracks the challenge scaffold only through
  `challenges/<event>/<category>/.gitkeep`; individual challenge workspaces
  under `challenges/<event>/<category>/<challenge>/` stay local by default.
- Challenge `notes.md`, `state.json`, and `replay.sh` may be tracked on
  explicit data/benchmark branches when intentionally sharing sanitized
  artifacts.
- `_selftest` challenge artifacts should not be committed.
- `benchmarks/*.md` and intentional benchmark scripts may be committed.

## Anti-Patterns

- Do not create separate workspaces per event.
- Do not place challenge-specific exploit scripts in root `tools/`.
- Do not use `_selftest` for real practice solves.
- Do not vendor broad external CTF repositories into the root workspace.
