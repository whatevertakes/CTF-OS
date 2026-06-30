# Hybrid Chain Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: source category skill material.
- Category-specific digests for each concrete boundary artifact.

## CTF-Relevant Patterns

- Name the boundary artifact that justifies every category switch.
- Keep source category evidence, intermediate artifacts, destination assumptions, and final proof scope separate.
- Run one category at a time with explicit stop conditions.
- Build one integrated replay path only after individual steps have evidence.

## CWE/CVE Mapping

- Use the destination category's CWE/CVE mapping only after the handoff artifact is preserved.
- Avoid category switching based on intuition or title alone.

## Canonical Papers And Deep Dives

- Use category-specific paper and CVE references after the boundary artifact identifies the relevant domain.

## When To Use

- Use when web leaks a binary, rev yields crypto parameters, forensics carves ciphertext, cloud yields container context, web3 yields crypto, or AI/ML yields concrete web/API effects.

## When Not To Use

- Do not use when a single category skill can solve the challenge directly.

## Source Anchors

- `idx:hybrid:upstream_ctf_skills:overview`
- `idx:hybrid:owasp_wstg:overview`
- `idx:hybrid:angr:overview`
- `idx:hybrid:rsactftool:overview`
- `idx:hybrid:volatility3:overview`
