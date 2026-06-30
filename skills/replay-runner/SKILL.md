purpose: Run a challenge `replay.sh`, preserve raw stdout/stderr evidence, write a redacted summary, and update state evidence paths.
when_to_use:
- A challenge has a replay script that should prove or preserve progress.
- A solver needs a stable log before proof validation.
when_not_to_use:
- No challenge directory or `replay.sh` exists yet.
inputs:
- Challenge directory path.
outputs:
- `evidence/replay_<UTC timestamp>.log`.
- `evidence/replay_<UTC timestamp>.summary.md`.
- Updated `state.json` evidence metadata when present, including replay kind and remote liveness.
- Process exit code matching `replay.sh`.
dependencies:
- `tools/replay_runner.py`
- `bash`
evidence produced:
- Raw replay log with command, cwd, stdout, stderr, and exit code.
- Redacted replay summary for safe reporting.
failure/blocker classes:
- Missing `replay.sh`.
- Non-zero replay exit.
- Replay depends on unrecorded state.
- Sensitive raw replay without a generated summary.
- `metadata.replay_kind` is `remote_live` or `remote_live_exploit` and the user did not explicitly opt in with `--allow-remote-live`.
future agent consumers:
- Solver.
- Proof validator.
- Benchmark runner.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `benchmarks/LEVEL2_SELFTEST.md`
