purpose: Run the Level 2 self-test benchmark to verify intake, replay, and proof validation.
when_to_use:
- After changing Level 2 scripts, templates, registry, or proof behavior.
- Before handing off the capability layer to another agent.
when_not_to_use:
- A challenge-specific solve needs focused analysis instead of layer validation.
inputs:
- Workspace root.
- Benchmark instructions.
outputs:
- Self-test challenge directory, replay log, proof validation output, and git status check.
dependencies:
- `benchmarks/LEVEL2_SELFTEST.md`
- `tools/intake_challenge.py`
- `tools/replay_runner.py`
- `tools/proof_validate.py`
evidence produced:
- `challenges/_selftest/misc/dummy/evidence/replay_*.log`.
failure/blocker classes:
- Intake rejects path.
- Replay script fails.
- Proof validation rejects default state.
future agent consumers:
- Benchmark runner.
- Reviewer.
- Future Level 2 maintainer.
pointers:
- `benchmarks/LEVEL2_SELFTEST.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
