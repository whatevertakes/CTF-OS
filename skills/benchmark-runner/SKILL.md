purpose: Run the workspace self-test benchmarks for Level 2 capability, Level 3 orchestration, and Level 4 interfaces.
when_to_use:
- After changing Level 2 scripts, Level 3 orchestration, Level 4 interfaces, templates, registry, or proof behavior.
- Before handing off the capability layer to another agent.
when_not_to_use:
- A challenge-specific solve needs focused analysis instead of layer validation.
inputs:
- Workspace root.
- Benchmark instructions.
outputs:
- Self-test challenge directories, replay logs, proof validation output, Level 3 board artifacts, and Level 4 interface reports.
dependencies:
- `benchmarks/LEVEL2_SELFTEST.md`
- `benchmarks/LEVEL3_SELFTEST.md`
- `benchmarks/LEVEL4_SELFTEST.md`
- `tools/preflight_check.py`
- `tools/intake_challenge.py`
- `tools/replay_runner.py`
- `tools/proof_validate.py`
- `tools/level3_orchestrator.py`
- `tools/level4_interface.py`
evidence produced:
- `challenges/_selftest/misc/dummy/evidence/replay_*.log`.
- `challenges/_selftest/misc/dummy/evidence/replay_*.summary.md`.
failure/blocker classes:
- Intake rejects path.
- Replay script fails.
- Proof validation rejects default state.
- Remote live replay guard does not block without explicit opt-in.
future agent consumers:
- Benchmark runner.
- Reviewer.
- Future Level 2-4 maintainer.
pointers:
- `benchmarks/LEVEL2_SELFTEST.md`
- `benchmarks/LEVEL3_SELFTEST.md`
- `benchmarks/LEVEL4_SELFTEST.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL3_DESIGN_NOTES.md`
- `docs/LEVEL4_INTERFACES.md`
