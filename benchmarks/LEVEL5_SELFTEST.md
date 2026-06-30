# Level 5 Self-Test Benchmark

The Level 5 self-test verifies bounded automation around existing Level 2
workflows only.

Run:

```bash
python3 benchmarks/level5_selftest.py
```

The benchmark checks that:

- `tools/preflight_check.py` recognizes Level 5 automation files.
- `tools/benchmark_runner.py dummy` runs a local dummy fixture outside
  `challenges/_selftest`.
- The benchmark runner prints exact commands and writes a sanitized
  `work/BENCHMARK_RUNNER_REPORT.md`.
- `tools/replay_runner.py` refuses missing, non-executable, or shebang-less
  `replay.sh` and runs valid replays as `./replay.sh`.
- Solved claims without replay evidence and blocked claims without blocker
  reasons fail closed.
- `tools/report_sanitize.py` redacts flag-like strings.
- `tools/cleanup_artifacts.py` removes only targeted, marker-bearing temporary
  `_selftest` and `_level5...` artifacts, prunes empty temp parents, preserves
  `challenges/.gitkeep`, and refuses real challenge work.

This benchmark does not run blind category coverage and does not add solving
capability.
