---
name: ctf-crypto
description: Solve cryptography challenges with explicit parameters, assumptions, scripts, and proof artifacts.
---

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
- Optional RsaCtfTool, Sage, z3, fplll, and pari-gp/gp references when
  required by the observed primitive.
reference_digest:
- `docs/reference-digests/crypto.md`
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
workflow:
- Extract exact parameters, encodings, ciphertexts, public keys, source code, transcripts, oracle endpoints, and sample pairs.
- Normalize numeric values and byte encodings in a local script before choosing an attack.
- Write the attack assumption in `notes.md`, including primitive, weakness, query model, and verification condition.
- Separate parameter extraction, oracle modeling, attack implementation, and independent verifier artifacts.
- Use RsaCtfTool for RSA public-key/modulus cases with known attack families;
  record the key material and selected attack output.
- Use Sage only when the math structure justifies it; keep a deterministic Python verifier when possible.
- Use z3 for explicit finite constraints, fplll for lattice reductions, and
  gp/pari-gp for number-theory calculations when those primitives are
  evidenced by parameters.
- Record oracle input, output, error class, timing, rate limit, and query budget before adaptive exploitation.
- Save recovered plaintext, key, seed, nonce, or flag proof under `evidence/`, and make `replay.sh` reproduce the final check.
first_commands:
- `python3 work/parse_params.py`
- `RsaCtfTool --publickey <pubkey> --uncipherfile <ciphertext>` when RSA key/ciphertext evidence exists.
- `sage work/attack.sage` when Sage is justified.
- `python3 work/solve_z3.py` when an SMT model is justified.
- `fplll <lattice-file>` or `gp -q < work/attack.gp` when lattice or PARI/GP math is justified.
- `python3 work/solve.py`
- `python3 work/verify.py`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
