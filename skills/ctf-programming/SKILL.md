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
reference_digest:
- `docs/reference-digests/programming.md`
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
workflow:
- Extract constraints, sample inputs, sample outputs, protocol grammar, time limits, and scoring rules.
- Write local sample tests before remote automation.
- Build deterministic solvers under `work/`, with timeouts and explicit failure handling.
- Capture interactive remote transcripts, generated inputs, and final output when they materially prove the solve.
- Make `replay.sh` run the solver or a saved transcript verifier.
- Escalate to crypto, rev, pwn, or web when the hard part becomes category-specific rather than algorithmic.
first_commands:
- `python3 work/solve.py < sample.txt`
- `python3 work/test_solver.py`
- `timeout 30 python3 work/remote_solve.py`
- `python3 tools/replay_runner.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
