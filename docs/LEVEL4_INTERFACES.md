# Level 4 Interfaces

Level 4 is the human-facing interface layer for this CTF workspace. It exposes
the Level 1 configuration, Level 2 challenge state and evidence, and Level 3
orchestration board through compact CLI, editor, terminal, browser, and report
surfaces.

It is not a new solve engine and not a parallel truth store.

## Implemented Runtime

`tools/level4_interface.py` provides:

- `build <challenge-dir>`: write `work/LEVEL4_INTERFACE.json` and
  `work/LEVEL4_STATUS.md`, then update `state.json.metadata` with pointers to
  those generated views.
- `doctor <challenge-dir>`: check the challenge contract, Level 1 MCP
  availability, Level 2 proof validation, and browser-interface readiness.
- `status <challenge-dir>`: print the current Level 4 status report, using the
  generated manifest when present.

Generated challenge-local files:

```text
work/LEVEL4_INTERFACE.json
work/LEVEL4_STATUS.md
```

State metadata written by `build`:

```text
metadata.level4_status
metadata.level4_version
metadata.level4_manifest
metadata.level4_report
```

## Required Interface With Level 1-3

Level 4 reads these lower-level contracts directly:

| Source | Files or settings | Level 4 use |
|---|---|---|
| Level 1 | `.codex/config.toml` | Detect MCP availability, approval policy, sandbox policy, and configured Playwright/radare2 routing. |
| Level 2 | `state.json`, `notes.md`, `replay.sh`, `evidence/`, `tools/replay_runner.py`, `tools/proof_validate.py` | Present challenge status, proof scope, replay commands, evidence inventory, and proof validation output. |
| Level 3 | `work/LEVEL3_STATE.json`, `work/LEVEL3_TASKS.json`, `work/LEVEL3_DISPATCH.*`, `work/LEVEL3_RUN_LOG.jsonl` | Present worker board state, dispatch files, task count, workers, and run-log visibility. |

The Level 4 manifest may point to Level 3 artifacts, but Level 2 `state.json`
remains the source of truth for solve status and proof scope.

## Interface Surfaces

| Surface | Contract |
|---|---|
| CLI | Emit exact commands for preflight, replay, proof validation, Level 3 status/evaluation, and Level 4 rebuild/doctor/status. |
| Editor | List the files a human should open first: `state.json`, `notes.md`, `replay.sh`, Level 3 board files when present, and Level 4 reports. |
| Terminal | Define repeatable terminal profiles for proof loops, evidence inventory, and Level 3 board watching. |
| Browser / Playwright | Expose Playwright only as a configured interface for browser-relevant categories; screenshots and traces belong under `evidence/`. |
| Report | Generate `work/LEVEL4_STATUS.md` as a challenge-local dashboard-style report without requiring a web server. |

## Organic Connection Rule

Level 4 must not reinterpret lower-level truth:

- Do not infer `solved`; call `tools/proof_validate.py`.
- Do not rerun remote live exploits; Level 2 `metadata.replay_kind` still
  controls replay safety.
- Do not create separate task state; read Level 3 artifacts when present.
- Do not make browser automation the default; use Playwright only when a local
  or owned target is evidenced.
- Do not put challenge-specific solve scripts in root `tools/`; keep them in
  the challenge `work/` directory.

## Self-Test

Run this after changing Level 4 behavior:

```bash
python3 benchmarks/level4_selftest.py
```

The self-test creates a temporary web challenge, initializes a Level 3 board,
builds the Level 4 interface, verifies the generated manifest/report, checks
state metadata pointers, and runs the Level 4 doctor/status commands.
