---
name: ctf-level3-orchestrator
description: Coordinate difficult CTF solves across bounded role-specific workers while preserving the Level 0-2 evidence contract.
---

purpose: Coordinate difficult CTF solves across bounded role-specific workers while preserving the Level 0-2 evidence contract.
when_to_use:
- A challenge has several plausible branches and a single linear solve loop is repeating negative probes.
- Remote lifetime, state mutation, or multi-service behavior requires parallel bookkeeping.
- A benchmark resembles `mikuprotect` deadline pressure or `DreamFlow` multi-branch web failure.
when_not_to_use:
- A single category skill can still make direct progress.
- There is no challenge workspace with `state.json`, `notes.md`, and `replay.sh`.
inputs:
- Challenge directory.
- Current `state.json`, `notes.md`, replay summaries, and proof validation output.
- Category skill and optional hybrid-chain guidance.
outputs:
- Worker task packets with objective, inputs, request/time budget, artifact path, and stop condition.
- `work/LEVEL3_STATE.json` and `work/LEVEL3_TASKS.json`.
- `work/LEVEL3_DISPATCH.json` and `work/LEVEL3_DISPATCH.md` for `multi_agent_v1.spawn_agent` operation.
- `work/LEVEL3_RUN_LOG.jsonl` for append-only orchestration events.
- `work/ATTEMPT_MATRIX.md` for broad negative probe catalogs.
- `work/MUTATION_LEDGER.md` when remote state changes.
- Updated `state.json`, `notes.md`, replay evidence, and proof validation output.
dependencies:
- `tools/level3_orchestrator.py`
- `tools/preflight_check.py`
- `tools/replay_runner.py`
- `tools/proof_validate.py`
- `docs/LEVEL2_TO_LEVEL3_HANDOFF.md`
- `docs/CTF_SOLVER_MEMORY.md`
reference_digest:
- `docs/reference-digests/common.md`
evidence produced:
- Worker evidence files.
- Positive facts and negative results with reproducible commands or saved responses.
- Replay logs and redacted summaries.
workflow:
- Run `python3 tools/level3_orchestrator.py init <challenge-dir>`.
- Run `python3 tools/level3_orchestrator.py plan <challenge-dir>`.
- Confirm each packet includes `inputs.skill` and `inputs.solve_playbook`, and that the worker reads both before probing.
- Use `packet` for a single worker preview, or `dispatch` to create spawn-ready packets.
- When using real sub-agents, main Codex reads `work/LEVEL3_DISPATCH.json`, calls `multi_agent_v1.spawn_agent` per packet, and records ids with `assign`.
- Put returned worker JSON files under `work/level3_results/`, then run `collect`.
- Re-running `collect` on the same result path must be a no-op; use a new worker or explicit review instead of overwriting merged worker history.
- Run `evaluate --run-replay`; remote live replay stays guarded by Level 2 metadata.
first_commands:
- `python3 tools/level3_orchestrator.py init <challenge-dir>`
- `python3 tools/level3_orchestrator.py plan <challenge-dir>`
- `python3 tools/level3_orchestrator.py dispatch <challenge-dir> --limit 2`
- `python3 tools/level3_orchestrator.py evaluate <challenge-dir> --run-replay`
v3 worker strategy:
- Every packet must include `strategy.playbook`, `strategy.tools`, `strategy.evidence_required`, and `strategy.failure_modes`.
- Web workers split auth, source/XXE, policy oracle, mutation, render/upload, and SSRF branches.
- Pwn workers include deadline-aware remote handling without implicit live replay.
- Rev workers include bounded symbolic execution and patch/unpatched verification.
- Crypto workers include parameter extraction, oracle modeling, attack script, and independent verifier.
- Forensics workers include inventory, timeline, carving, memory/network, and crypto bridge.
failure/blocker classes:
- Worker returns hypotheses without evidence.
- Remote expires before replay/proof metadata is updated.
- Mutation side effects are not recorded.
- Workers repeat known-negative payload families.
- Main agent spawns workers but does not run `collect`, leaving Level 2 proof state stale.
future agent consumers:
- Level 3 orchestrator.
- Category workers.
- Proof and evidence worker.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL3_DESIGN_NOTES.md`
- `docs/LEVEL2_TO_LEVEL3_HANDOFF.md`
- `docs/CTF_SOLVER_MEMORY.md`
- `benchmarks/level3_selftest.py`
- `challenges/_selftest/web/DreamFlow/work/LEVEL3_WORKER_TASKS.md`
