---
name: ctf-web
description: Analyze web CTF targets through concrete requests, responses, client behavior, and server-side effects.
---

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
- Optional arjun for parameter discovery after a route baseline exists.
- Optional flask-unsign for evidenced Flask signed cookie handling.
- Optional sqlmap for an evidenced SQL injection hypothesis after request shape
  and risk are bounded.
- Optional ffuf or gobuster for scoped route/content discovery after baseline
  routes and rate limits are known.
- Optional wafw00f and shodan for scoped fingerprinting and public challenge
  target context.
- Optional Burp Suite or Caido as external GUI proxies when manual HTTP
  inspection materially shapes the solve.
reference_digest:
- `docs/reference-digests/web.md`
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
- Use arjun only after baseline routes and methods are known; record the target
  URL, wordlist assumptions, and discovered parameters.
- Use flask-unsign only when a Flask signed cookie or secret-key hypothesis is
  evidenced; save the cookie sample and verification command.
- Use wafw00f for WAF fingerprinting only when filtering behavior affects
  payload interpretation.
- Use shodan only for challenge-owned or explicitly scoped public targets, and
  record the query and access date.
- Use sqlmap only after a concrete parameter, header, cookie, or body field has
  an SQLi signal; preserve the raw request and selected options.
- Use ffuf or gobuster only with scoped wordlists, bounded recursion, and saved
  status/length filters.
- Log every state-changing remote action in `work/MUTATION_LEDGER.md` with before, after, target, action, and evidence.
- Write negative families to `work/ATTEMPT_MATRIX.md`; avoid counting simple encoding variants as new hypotheses.
- Escalate to rev, pwn, crypto, or jail only when a concrete artifact or behavior changes domain.
first_commands:
- `python3 - <<'PY'` with `requests.Session()` for reproducible route inventory when source is not enough.
- `curl -i <url>` for saved baseline responses.
- `arjun -u <url>` after baseline route inventory shows unknown parameters.
- `flask-unsign --decode --cookie <cookie>` when Flask cookie signing is evidenced.
- `wafw00f <url>` when WAF behavior affects probe interpretation.
- `sqlmap -r work/request.txt --batch --risk 1 --level 1` after an SQLi signal is evidenced.
- `ffuf -u <url>/FUZZ -w <wordlist> -mc all` or `gobuster dir -u <url> -w <wordlist>` when content discovery is scoped.
- `.codex/bin/tplmap` only after a concrete template render path exists.
- `.codex/bin/searchsploit` only when a product/version is evidenced.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL0_INFRASTRUCTURE.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
