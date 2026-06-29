purpose: Analyze web CTF targets through concrete requests, responses, client behavior, and server-side effects.
when_to_use:
- The primary artifact is a web app, API, browser challenge, HTTP transcript, or URL.
- A hybrid chain starts from web behavior.
when_not_to_use:
- The only useful artifact is already a native binary, crypto primitive, or memory image.
inputs:
- URL, local app files, request samples, cookies, source code, or browser state.
outputs:
- Reproducible requests, payloads, response evidence, and next-step routing.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional Playwright MCP for browser interactions.
evidence produced:
- Saved request/response pairs, payloads, screenshots when useful, and replay commands.
failure/blocker classes:
- Missing target access.
- Non-reproducible session state.
- Rate limits or third-party systems outside challenge scope.
future agent consumers:
- Web solver.
- Hybrid-chain solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
