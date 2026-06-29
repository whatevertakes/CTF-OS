purpose: Run a challenge `replay.sh` and preserve stdout, stderr, cwd, command, and exit code under evidence.
when_to_use:
- A challenge has a replay script that should prove or preserve progress.
- A solver needs a stable log before proof validation.
when_not_to_use:
- No challenge directory or `replay.sh` exists yet.
inputs:
- Challenge directory path.
outputs:
- `evidence/replay_<UTC timestamp>.log`.
- Process exit code matching `replay.sh`.
dependencies:
- `tools/replay_runner.py`
- `bash`
evidence produced:
- Replay log with command, cwd, stdout, stderr, and exit code.
failure/blocker classes:
- Missing `replay.sh`.
- Non-zero replay exit.
- Replay depends on unrecorded state.
future agent consumers:
- Solver.
- Proof validator.
- Benchmark runner.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `benchmarks/LEVEL2_SELFTEST.md`
