---
name: ctf-misc
description: Route ambiguous or unconventional challenges while preserving evidence until a narrower category emerges.
---

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
reference_digest:
- `docs/reference-digests/misc.md`
evidence produced:
- Artifact list, command notes, and routing decision.
failure/blocker classes:
- Insufficient prompt or missing artifacts.
- Multiple plausible domains without a discriminating test.
future agent consumers:
- Category router.
- Any category solver.
workflow:
- Treat misc as a router until evidence proves a narrower domain.
- Inventory files, prompts, remote protocol samples, constraints, scoring rules, and hidden-state clues.
- Build a minimal state model before automation: states, tokens, grammar, transitions, and failure responses.
- Use parser-state probes for serialization, compression, Unicode, archive, image, and encoding ambiguity.
- Write deterministic automation under `work/`, with samples, timeouts, retries, and saved transcripts.
- Escalate only when an artifact proves a category change, such as key material for crypto, binary logic for rev, memory corruption for pwn, or HTTP behavior for web.
- If manual progress matters, convert it into a replayable script or saved transcript before claiming progress.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `python3 work/solve.py`
- `python3 tools/replay_runner.py <challenge-dir>` after a replay path exists.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
