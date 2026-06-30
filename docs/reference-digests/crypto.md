# Crypto Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: crypto subskills for RSA, ECC, lattice, PRNG, stream ciphers, ZKP, and modern modes.
- `ref:rsactftool`: RSA weakness taxonomy and tooling reference.
- `ref:crypto_attacks`: CTF-focused attack implementations.
- `ref:sage`: math environment reference.

## CTF-Relevant Patterns

- Extract exact parameters, encodings, source, samples, oracle contract, rate limits, and query budget before choosing an attack.
- Separate parameter extraction, model, attack, and independent verifier.
- Classify primitive before coding: RSA, ECC, lattice/LWE, PRNG, stream cipher, block mode, hash/MAC/signature, commitment, ZK, or custom algebra.
- Use Sage only when math structure justifies it; keep a deterministic verifier where possible.

## CWE/CVE Mapping

- Map weak randomness, nonce reuse, padding oracle, and broken signature verification to CWE classes only after transcript or parameter evidence.
- CVEs are secondary unless a known library/version is part of the challenge.

## Canonical Papers And Deep Dives

- Coppersmith, Boneh-Durfee, Bleichenbacher, lattice reduction, MT19937 recovery, and nonce-reuse literature are core deep-dive references.
- Use paper claims only after local parameters match assumptions.

## When To Use

- Use for ciphertexts, keys, public parameters, signing/encryption oracles, custom algebra, PRNGs, commitments, and ZK-like protocols.

## When Not To Use

- Do not use when the task is only file carving, source disclosure, request construction, or binary extraction.

## Source Anchors

- `idx:crypto:upstream_ctf_skills:overview`
- `idx:crypto:rsactftool:overview`
- `idx:crypto:crypto_attacks:overview`
- `idx:crypto:sage:overview`
