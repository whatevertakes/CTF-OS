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
- Pass/fail proof validation result, proof scope, remote status, replay kind, remote liveness, sensitive log count, and blocker reason when invalid.
dependencies:
- `tools/proof_validate.py`
evidence produced:
- Validation command output and any referenced replay logs.
failure/blocker classes:
- Invalid status.
- `solved` without `final_command`.
- `solved` without replay evidence.
- Missing evidence paths referenced by `state.json`.
- Missing required metadata fields for proof scope, remote status, replay kind, liveness, or evidence sensitivity.
- Sensitive replay log without a redacted summary.
- `partial` without evidence or a blocker reason.
- Remote failure marked as solved without local proof-scope metadata.
future agent consumers:
- Proof validator.
- Reviewer.
- Solver.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `benchmarks/LEVEL2_SELFTEST.md`
