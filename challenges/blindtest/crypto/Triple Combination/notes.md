# Challenge Notes

## Summary

- Event: blindtest
- Category: crypto
- Name: Triple Combination
- Prompt: Can you eat three combination pizzas at once?
- Status: solved
- Local proof recovers the structured RSA factors from the digit-reversal construction and verifies the decrypted plaintext by re-encrypting it.

## Artifacts

- Original handout: `dist/Triple Combination.zip`
- Handout SHA-256: `e0868df9a5c684722c4ed02d50944a1ab9b3b0ae3156fd8043147ccfe6eaec7d`
- Extracted files under `work/extracted/`: `chal.py`, `output.txt`
- Extracted file inventory: `work/file.txt`
- Extracted SHA-256 inventory: `work/sha256sum.txt`
- Solver: `work/solve.py`

## Observations

- `chal.py` generates 256-bit primes `p`, `q`, and `r`.
- It builds two RSA primes as base-`2^256` digit reversals:
  `a = p*B^2 + q*B + r` and `b = r*B^2 + q*B + p`.
- The public modulus is `N = a*b`, with `e = 65537`.
- Since `a == b mod (B^2 - 1)`, `N` has a square root modulo `M = B^2 - 1` equal to `q*B + (p+r)`.
- The original ZIP is preserved in `dist/`; extracted and generated analysis files are under `work/`.

## Hypotheses

- The intended weakness is the digit-reversal relation between the two RSA factors, not generic RSA factoring.
- Recovering a modular square root of `N mod (2^512 - 1)` should reveal `q` and `p+r`.
- With `q` and `s = p+r`, the product `t = p*r` follows from the expanded equation, then `p` and `r` are roots of `X^2 - sX + t`.

## Attempts

- Ran the intake helper, but it rejected the space-containing challenge name. Existing workspace challenges use display names with spaces, so the required directory was created manually from the template.
- Tried general-purpose SymPy factorization of `2^512 - 1`; it was too slow and was stopped.
- Used the Fermat-number decomposition of `2^512 - 1`, verified in `work/solve.py` by checking the factor product before computing CRT-combined square roots.
- Solver recovered `p`, `q`, `r`, verified both structured factors are prime, checked `a*b == N`, and verified the ciphertext roundtrip.

## Tool Routing Decision

- Primary tools used: local Python, PyCryptodome, SymPy modular roots/CRT, replay runner, sanitizer.
- Considered: Sage, RsaCtfTool, radare2/angr MCP, Playwright, Burp.
- Used: `unzip` for handout extraction, `file` and `sha256sum` for artifact evidence, Python solver for structured RSA recovery, `tools/replay_runner.py` for replay evidence, `tools/report_sanitize.py --check` for sensitive-log redaction.
- Skipped: Sage was not needed because the modular-root/CRT math is small enough in Python; RsaCtfTool was skipped because this is a custom structured-prime weakness; radare2/angr were skipped because there is no native binary; Playwright and Burp were skipped because there is no web target or remote HTTP behavior.
- Missing: none.
- Decision summary: Local artifact analysis was sufficient. No MCP tool was materially useful for this Python/RSA handout.

## Blocker or Solve

- Solved with local replay.
- Final command: `python3 tools/replay_runner.py "challenges/blindtest/crypto/Triple Combination"`
- Proof scope: local RSA factor recovery and ciphertext-roundtrip plaintext validation.
- Remote status: no remote provided.

## Evidence

- Raw replay log: `evidence/replay_20260701T044407Z.log`
- Redacted replay summary: `evidence/replay_20260701T044407Z.summary.md`
- Final raw replay log: `evidence/replay_20260701T044558Z.log`
- Final redacted replay summary: `evidence/replay_20260701T044558Z.summary.md`
- Proof validation output: `evidence/proof_validate.txt`
