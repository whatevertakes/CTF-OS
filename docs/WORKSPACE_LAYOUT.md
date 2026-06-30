# CTF Workspace Layout Contract

This document defines the permanent layout contract for
`/home/choijiwng/02_ctf_workspace`.

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

- `state.json`: machine-readable status, `final_command`, blocker,
  `next_action`, evidence paths, proof scope, remote status, replay kind,
  remote liveness, evidence sensitivity, and metadata.
- `notes.md`: human-readable solve log.
- `replay.sh`: reproducible proof or replay entrypoint.
- `evidence/`: replay logs, redacted replay summaries, screenshots, and final
  proof outputs.
- `dist/`: original challenge handouts, binaries, `docker-compose`, and
  provided files.
- `work/`: scratch scripts, exploit drafts, extracted files, and local
  analysis. Level 3 and Level 4 generated board/interface files also live here.

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
- Raw replay logs that contain flag-like markers must have a matching redacted
  `*.summary.md` file before proof validation succeeds.
- Live remote exploit replays should set `metadata.replay_kind` to
  `remote_live` or `remote_live_exploit`; `replay_runner.py` will then require
  explicit `--allow-remote-live` opt-in.
- Level 4 interface views are generated with `tools/level4_interface.py`; they
  may add `metadata.level4_*` pointers but must not replace proof validation or
  create a separate solve status.

## Git Policy

- Do not commit secrets, flags, tokens, huge dumps, core files, or private keys.
- Challenge `notes.md`, `state.json`, and `replay.sh` may be tracked locally.
- `_selftest` challenge artifacts should not be committed.
- `benchmarks/*.md` and intentional benchmark scripts may be committed.

## Anti-Patterns

- Do not create separate workspaces per event.
- Do not place challenge-specific exploit scripts in root `tools/`.
- Do not use `_selftest` for real practice solves.
- Do not vendor broad external CTF repositories into the root workspace.
