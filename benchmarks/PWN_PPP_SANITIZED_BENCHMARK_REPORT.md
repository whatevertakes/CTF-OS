# pwn_ppp Sanitized Benchmark Report

- benchmark_id: `pwn_ppp`
- category: `pwn`
- role: positive remote-solve control
- sanitized_status: remote solved
- proof_scope: remote proof observed during prior benchmark run
- raw_flag_committed: no
- raw_replay_log_committed: no
- evidence_sensitivity: contains flag in raw evidence; sanitized report only

## Retained Evidence

The retained commit-safe evidence is limited to the benchmark outcome and safety
lesson:

- `pwn_ppp` demonstrated that pwn remote-solve evidence can contain real flags.
- Raw replay logs and transcripts for this case must not be committed.
- Downstream workers must separate raw evidence from redacted reporting.

## Source References

- `docs/CTF_SOLVER_MEMORY.md` records `pwn_ppp` as the positive remote-solve
  control for sensitive replay handling and remote proof scope.
- `docs/LEVEL3_DESIGN_NOTES.md` records the Level 3 design constraint that
  `pwn_ppp` remote-solved evidence can contain real flags.

## Redaction Boundary

This report intentionally excludes:

- the flag
- raw remote transcript
- raw replay log
- exploit payload bytes
- target connection details

This file is suitable for commit as a sanitized benchmark evidence record. It is
not a substitute for raw replay evidence during live challenge solving.
