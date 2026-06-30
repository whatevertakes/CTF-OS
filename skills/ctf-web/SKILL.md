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
- Optional `.codex/bin/tplmap` for SSTI detection and exploitation.
- Optional `.codex/bin/searchsploit` for CVE and public exploit lookup.
evidence produced:
- Saved request/response pairs, payloads, screenshots when useful, and replay commands.
failure/blocker classes:
- Missing target access.
- Non-reproducible session state.
- Rate limits or third-party systems outside challenge scope.
future agent consumers:
- Web solver.
- Hybrid-chain solver.
workflow:
- Freeze base URL, local source, docker-compose, credentials, roles, cookies, and request samples before payload work.
- Inventory routes, methods, content types, auth/session transitions, upload/render paths, background jobs, and state-changing endpoints.
- Save representative requests, responses, screenshots, HTML, and JSON under `evidence/` or `work/html/`.
- Split branches into auth/session, source disclosure, policy oracle, mutation, render/runtime, and SSRF/internal probes.
- Log every state-changing remote action in `work/MUTATION_LEDGER.md` with before, after, target, action, and evidence.
- Write negative families to `work/ATTEMPT_MATRIX.md`; avoid counting simple encoding variants as new hypotheses.
- Escalate to rev, pwn, crypto, or jail only when a concrete artifact or behavior changes domain.
first_commands:
- `python3 - <<'PY'` with `requests.Session()` for reproducible route inventory when source is not enough.
- `curl -i <url>` for saved baseline responses.
- `.codex/bin/tplmap` only after a concrete template render path exists.
- `.codex/bin/searchsploit` only when a product/version is evidenced.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL0_INFRASTRUCTURE.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
