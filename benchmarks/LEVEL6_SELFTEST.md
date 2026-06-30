# Level 6 Self-Test Benchmark

The Level 6 self-test verifies read-only corpus evaluation and regression
gating. It does not add solving capability, run remote targets, run replay, or
delete existing challenge work.

Run:

```bash
python3 benchmarks/level6_selftest.py
```

The benchmark checks that:

- `tools/evaluate_corpus.py` handles planned entries.
- solved entries without replay proof evidence are flagged.
- blocked entries without blocker reasons are flagged.
- missing challenge paths are reported.
- category counts work.
- split counts work.
- `tools/regression_check.py` skips replay by default.
- generated evaluation output does not contain raw flag markers.

Fixtures are created under a unique Python temporary directory and removed by
the tempfile context manager. No `challenges/` paths are created or deleted.
