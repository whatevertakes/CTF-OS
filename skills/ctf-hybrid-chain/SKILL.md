purpose: Coordinate solves where evidence crosses CTF category boundaries.
when_to_use:
- A source artifact from one category produces a concrete artifact for another category.
- The requested chain matches one documented hybrid workflow.
when_not_to_use:
- A single category skill can solve the challenge directly.
inputs:
- Source artifact path, boundary evidence, current category notes, and next artifact type.
outputs:
- Ordered chain, category handoff notes, replay command, and proof validation status.
dependencies:
- `skills/ctf-triage/SKILL.md`
- `tools/replay_runner.py`
- `tools/proof_validate.py`
reference_digest:
- `docs/reference-digests/hybrid.md`
evidence produced:
- Boundary transcript, intermediate artifacts, final replay log, and proof validation output.
failure/blocker classes:
- Missing source artifact.
- Category switch based on assumption rather than evidence.
- Final proof cannot be replayed.
future agent consumers:
- Hybrid-chain solver.
- Reviewer.
- Proof validator.
workflow:
- Name the concrete boundary artifact that justifies every category switch.
- Keep source category evidence, intermediate artifacts, destination category assumptions, and final proof scope separate.
- Run one category at a time with explicit stop conditions.
- Preserve handoff notes and artifacts under `work/` and `evidence/`.
- Build one integrated replay path only after individual steps have evidence.
- Validate the final proof through `tools/replay_runner.py` and `tools/proof_validate.py`.
first_commands:
- `python3 tools/proof_validate.py <challenge-dir>`
- `python3 tools/replay_runner.py <challenge-dir>`
- `python3 tools/level3_orchestrator.py plan <challenge-dir> --category hybrid`
- `python3 tools/level3_orchestrator.py evaluate <challenge-dir> --run-replay`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
