purpose: Check whether challenge state and evidence support the current claimed status.
when_to_use:
- Before claiming solved.
- During review of a partial or blocked solve.
- After replay evidence is generated.
when_not_to_use:
- Before a challenge directory and `state.json` exist.
inputs:
- Challenge directory containing `state.json` and optional replay logs.
outputs:
- Pass/fail proof validation result and blocker reason when invalid.
dependencies:
- `tools/proof_validate.py`
evidence produced:
- Validation command output and any referenced replay logs.
failure/blocker classes:
- Invalid status.
- `solved` without `final_command`.
- `solved` without replay evidence.
future agent consumers:
- Proof validator.
- Reviewer.
- Solver.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `benchmarks/LEVEL2_SELFTEST.md`
