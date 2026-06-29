purpose: Route ambiguous or unconventional challenges while preserving evidence until a narrower category emerges.
when_to_use:
- The category is unknown, mixed, puzzle-like, or not covered by a more specific skill.
when_not_to_use:
- Evidence clearly points to web, pwn, reverse, crypto, forensics, or another named skill.
inputs:
- Challenge prompt, files, service info, and early observations.
outputs:
- Minimal inventory, hypotheses, and recommended next category.
dependencies:
- `skills/ctf-triage/SKILL.md`
evidence produced:
- Artifact list, command notes, and routing decision.
failure/blocker classes:
- Insufficient prompt or missing artifacts.
- Multiple plausible domains without a discriminating test.
future agent consumers:
- Category router.
- Any category solver.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
