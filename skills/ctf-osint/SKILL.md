purpose: Conduct OSINT-style CTF work with source citations, timestamps, and reproducible search paths.
when_to_use:
- The challenge depends on public information, archives, geolocation, usernames, domains, or historical pages.
when_not_to_use:
- The target is private, real-world sensitive, or unrelated to the challenge scope.
inputs:
- Names, handles, images, domains, locations, time windows, or clue text.
outputs:
- Source list, reasoning chain, recovered answer, and access date notes.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional browser or Playwright MCP when evidence must be captured.
evidence produced:
- URLs, access dates, screenshots when useful, archived references, and notes.
failure/blocker classes:
- Ambiguous identity.
- Deleted or access-limited source.
- Privacy or scope concern.
future agent consumers:
- OSINT solver.
- Proof validator.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
