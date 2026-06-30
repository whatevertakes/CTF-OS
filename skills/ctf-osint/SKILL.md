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
reference_digest:
- `docs/reference-digests/osint.md`
evidence produced:
- URLs, access dates, screenshots when useful, archived references, and notes.
failure/blocker classes:
- Ambiguous identity.
- Deleted or access-limited source.
- Privacy or scope concern.
future agent consumers:
- OSINT solver.
- Proof validator.
workflow:
- Confirm challenge scope and avoid private, real-world sensitive, or unrelated targets.
- Record clue text, names, handles, domains, image metadata, location hints, time windows, and language assumptions.
- Track every source with URL, access date, archive link when available, and screenshot when useful.
- Disambiguate identities and locations with multiple independent clues.
- Tie the final answer to cited evidence rather than memory.
first_commands:
- `python3 tools/intake_challenge.py --event <event> --category osint --name <name>`
- Save source URLs and access dates in `notes.md`.
- Save screenshots or archived pages under `evidence/` when material.
- `python3 tools/proof_validate.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
