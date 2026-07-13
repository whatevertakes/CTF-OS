# Crypto playbook

## Scope and recon

Keep all calculations on challenge-supplied ciphertexts, public parameters, and oracle endpoints explicitly authorized by the manifest. Normalize integers, encodings, block sizes, known plaintext, nonce reuse clues, and all assumptions in a notebook or script. Preserve raw inputs before conversion.

## Hypotheses and tooling

Classify the construction before selecting an attack: RSA parameter relations, weak exponents, common modulus, reused randomness, stream/XOR reuse, ECB structure, LCG output, lattice structure, polynomial systems, discrete log, or factorization. Use SageMath, `RsaCtfTool`, PARI/GP, `fpylll`, `z3`, or CADO-NFS according to the mathematical precondition. An online oracle must be rate-conscious and limited to the listed CTF service.

## Validation and replay

Re-encrypt, decrypt, or independently recompute the claimed relation. Save parameters, script version, command line, intermediate checks, and final decoding rules. If an attack fails, record which mathematical precondition was absent before changing strategy.
