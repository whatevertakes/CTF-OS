purpose: Solve programming and PPC challenges with small deterministic parsers, solvers, and input/output evidence.
when_to_use:
- The challenge requires algorithmic solving, automation, parsing, or repeated remote interactions.
when_not_to_use:
- The hard part is exploitation, crypto analysis, or reverse engineering rather than algorithm design.
inputs:
- Prompt, sample inputs, protocol transcript, constraints, local files, or remote endpoint.
outputs:
- Solver script, test cases, final command, and captured output.
dependencies:
- `skills/ctf-triage/SKILL.md`
evidence produced:
- Sample tests, solver source, command output, and replay logs.
failure/blocker classes:
- Incomplete input specification.
- Time-sensitive remote protocol.
- Solver depends on unrecorded manual state.
future agent consumers:
- Programming solver.
- Replay runner.
- Proof validator.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
