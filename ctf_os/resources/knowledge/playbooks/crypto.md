# Crypto exploit-first playbook

## 1. Fast recon budget

Budget three observations: (1) normalize the supplied construction/parameters/encoding; (2) identify the single leading violated assumption; (3) run one known-answer or small-instance test. Then implement the leading attack immediately.

## 2. Highest-value exploit hypotheses

Choose at most three precondition-backed attacks: weak/related RSA parameters, nonce/randomness reuse, XOR/stream reuse, block-mode structure, predictable PRNG, lattice/polynomial relation, small discrete log, factorization, or oracle behavior.

## 3. Cheapest decisive experiments

Check one gcd/relation, recover one keystream segment, solve one reduced lattice/polynomial instance, predict one PRNG output, or query one rate-conscious oracle differential. A test must validate the mathematical precondition.

## 4. Immediate PoC criteria

A short script that succeeds on the known-answer/small instance and is parameterized for the real input is a working PoC. Scale it immediately; prefer executable output validation over a complete proof.

## 5. Remote transition criteria

Use the real parameters as soon as the small test succeeds. Contact only declared oracle endpoints and preserve query/output needed for provenance. Scheduler planning is only for genuinely long lattice/factor/cracking work.

## 6. Kill conditions

Kill when the necessary relation/precondition is absent, the reduced test fails, or computation shows no solver-linked constraint reduction in a bounded slice. Replace the mathematical mechanism rather than describing more possible attacks.

## 7. Common research-drift traps

Do not explain every possible cryptanalytic attack, prove the construction comprehensively, keep a notebook instead of a solver, generalize a crypto library, or delay real parameters after a small-instance success.

## 8. Flag fast path

Publish solver-linked constraint reduction and `WORKING_POC` first. Validate decoded output with the challenge behavior/pattern, preserve the script and parameters, and surface the flag immediately; independent proof/replay is optional.
