---
name: benchmark-runner
description: Run bounded workspace self-test benchmarks and Level 5 automation wrappers without adding solve capability.
---

purpose: Run bounded workspace self-test benchmarks and Level 5 automation wrappers without adding solve capability.
when_to_use:
- After changing Level 2 scripts, Level 3 orchestration, Level 4 interfaces, Level 5 automation wrappers, templates, registry, or proof behavior.
- Before handing off the capability layer to another agent.
when_not_to_use:
- A challenge-specific solve needs focused analysis instead of layer validation.
- The request would add new solvers, agents, remote push automation, Discord, or tool installation.
inputs:
- Workspace root.
- Benchmark instructions.
outputs:
- Self-test challenge directories, replay logs, proof validation output, Level 3 board artifacts, Level 4 interface reports, and Level 5 sanitized automation reports.
dependencies:
- `benchmarks/LEVEL2_SELFTEST.md`
- `benchmarks/LEVEL3_SELFTEST.md`
- `benchmarks/LEVEL4_SELFTEST.md`
- `benchmarks/LEVEL5_SELFTEST.md`
- `tools/preflight_check.py`
- `tools/benchmark_runner.py`
- `tools/intake_challenge.py`
- `tools/replay_runner.py`
- `tools/proof_validate.py`
- `tools/report_sanitize.py`
- `tools/cleanup_artifacts.py`
- `tools/level3_orchestrator.py`
- `tools/level4_interface.py`
evidence produced:
- `challenges/_selftest/misc/dummy/evidence/replay_*.log`.
- `challenges/_selftest/misc/dummy/evidence/replay_*.summary.md`.
- `challenges/_level5benchmark/misc/dummy-local/work/BENCHMARK_RUNNER_REPORT.md`.
failure/blocker classes:
- Intake rejects path.
- Replay script fails.
- Proof validation rejects default state.
- Remote live replay guard does not block without explicit opt-in.
- Level 5 automation attempts to use `challenges/_selftest` as benchmark input.
- Cleanup targets a real challenge path.
future agent consumers:
- Benchmark runner.
- Reviewer.
- Future Level 2-5 maintainer.
pointers:
- `benchmarks/LEVEL2_SELFTEST.md`
- `benchmarks/LEVEL3_SELFTEST.md`
- `benchmarks/LEVEL4_SELFTEST.md`
- `benchmarks/LEVEL5_SELFTEST.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL3_DESIGN_NOTES.md`
- `docs/LEVEL4_INTERFACES.md`
- `docs/LEVEL5_AUTOMATION_POLICY.md`
