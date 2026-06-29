purpose: Solve cryptography challenges with explicit parameters, assumptions, scripts, and proof artifacts.
when_to_use:
- The challenge exposes ciphertext, keys, oracles, signatures, hashes, commitments, PRNG, or custom crypto.
- Another category yields cryptographic material.
when_not_to_use:
- The task is only file carving, web request construction, or binary extraction.
inputs:
- Problem statement, ciphertext, public keys, oracle interface, recovered constants, or transaction data.
outputs:
- Solver script, derived key/plaintext, final command, and reasoning tied to parameters.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional RsaCtfTool or Sage references when required.
evidence produced:
- Parameter dump, solver code, command output, plaintext, and replay log.
failure/blocker classes:
- Missing modulus or parameters.
- Oracle unavailable or unstable.
- Mathematical assumption not supported by evidence.
future agent consumers:
- Crypto solver.
- Hybrid-chain solver.
- Proof validator.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
