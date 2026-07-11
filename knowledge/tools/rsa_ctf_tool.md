# RSA CTF Tool quick sheet

Run RSA helpers only on challenge-supplied public keys, ciphertexts, and local files. First record `n`, `e`, `c`, known plaintext assumptions, and byte order; then choose a tool mode that matches an evidenced weakness such as small exponent or common modulus.

Independently verify output with modular arithmetic or re-encryption. Preserve command lines and do not send nonessential requests to an oracle service.
