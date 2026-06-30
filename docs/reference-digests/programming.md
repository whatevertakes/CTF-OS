# Programming Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: misc automation and CTF navigation patterns.

## CTF-Relevant Patterns

- Extract constraints, sample inputs, sample outputs, protocol grammar, time limits, scoring rules, and hidden-state observations.
- Write local sample tests before remote automation.
- Build deterministic solvers under `work/` with timeouts, retries, and explicit failure handling.
- Preserve generated inputs, outputs, and final transcript when they prove the solve.

## CWE/CVE Mapping

- CVE/CWE generally does not apply unless the programming task pivots into a parser, web, crypto, or binary vulnerability.

## Canonical Papers And Deep Dives

- Algorithmic references should be problem-specific; record the chosen algorithm and complexity bound in notes.

## When To Use

- Use for PPC, interactive automation, parsing, combinatorics, optimization, and repeated remote interactions.

## When Not To Use

- Do not use when the hard part is crypto analysis, binary exploitation, reverse engineering, or web behavior.

## Source Anchors

- `idx:programming:upstream_ctf_skills:overview`
