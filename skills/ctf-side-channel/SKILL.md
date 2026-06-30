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
reference_digest:
- `docs/reference-digests/hardware-rf-side-channel.md`
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
workflow:
- Inventory raw traces, timing logs, oracle behavior, sample counts, metadata, source code, and hypotheses.
- Preserve raw measurements unchanged; write analysis scripts and derived data under `work/`.
- Define timing, power, cache, fault, or statistical leakage model with confidence and sample-size notes.
- Run bounded analysis and avoid claiming recovered secrets without independent deterministic verification.
- Route recovered parameters or cryptographic material to `ctf-crypto` after preserving trace evidence.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `python3 work/analyze_traces.py`
- `python3 work/verify_secret.py`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
