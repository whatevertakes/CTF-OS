purpose: Analyze timing, power, cache, fault, and trace-based side-channel CTF artifacts.
when_to_use:
- The challenge includes traces, timing data, repeated measurements, or leakage hypotheses.
when_not_to_use:
- There is no raw measurement or repeatable oracle.
inputs:
- Trace files, timing logs, oracle interface, sample metadata, source code, or hypothesis.
outputs:
- Leakage model, analysis script, recovered secret, and replayable validation.
dependencies:
- `skills/ctf-triage/SKILL.md`
- ChipWhisperer references only when useful.
evidence produced:
- Raw trace references, scripts, plots when necessary, recovered values, and replay logs.
failure/blocker classes:
- Too few samples.
- Missing measurement metadata.
- Non-reproducible oracle behavior.
future agent consumers:
- Side-channel solver.
- Crypto solver.
- Hardware/RF solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
