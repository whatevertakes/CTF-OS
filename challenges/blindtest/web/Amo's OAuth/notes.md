# Summary

Amo's OAuth is a four-service OAuth demo: public client-app, public auth-server, internal resource-server, and public admin bot. The flag is returned only when the resource server sees a valid JWT with `sub == "admin"`.

# Artifacts

- Original handout ZIP: `dist/Amo's OAuth.zip`
- Existing extracted source: `deploy/`
- Compose file: `docker-compose.yml`
- Solver: `work/solve.py`
- Replay entrypoint: `replay.sh`
- Baseline responses: `evidence/baseline_client_root.http`, `evidence/baseline_auth_root.http`, `evidence/baseline_bot_report.http`, `evidence/client_login_redirect.headers`

# Observations

- Auth server `/authorize` accepts any `redirect_uri` whose hostname ends with `.dreamhack.games`; it does not require an exact registered callback.
- Auth server `/token` stores the original redirect URI with the code but does not compare it during authorization-code redemption.
- Client app stores `AUTH_SERVER_URL_CURRENT` and `CLIENT_APP_URL_CURRENT` in process-global variables controllable through public POST routes.
- Client app `/callback` checks `req.query.state !== req.session.state`; in a fresh session with no stored state, omitting the `state` query passes the check.
- Bot submits administrator credentials to the OAuth login form reached from the supplied URL.
- DreamHack request-bin hosts end with `.request.dreamhack.games`, pass the redirect allowlist, and expose logs via `/_log/<hostname>` and `/_data/<request_id>`.

# Hypotheses

- A fresh DreamHack request-bin URL can be set as the client callback base, causing the admin bot's authorization code to be logged externally.
- The captured admin code can be redeemed through the client app in a fresh session by omitting `state`, allowing the client app to use its internal client secret and then call the resource API.

# Attempts

- Confirmed the live service mapping with baseline `curl` requests to ports `10841`, `13635`, and `10480`.
- Confirmed DreamHack request-bin creation and log retrieval.
- Implemented `work/solve.py` to create a new bin, mutate client-app globals, run the bot, poll for the admin code, redeem it, and call the protected API.

# Tool Routing Decision

- Primary tools used: local source review, `curl`, Python `requests`, BeautifulSoup, DreamHack request-bin.
- Considered: Playwright MCP, Burp proxy, `.codex/bin/tplmap`, `.codex/bin/searchsploit`, radare2/angr MCP.
- Used: direct HTTP tooling because the OAuth state transitions and bot behavior were fully visible in source and could be replayed deterministically.
- Skipped: Playwright MCP because no client-only behavior was required; Burp because low-volume direct HTTP requests were sufficient; tplmap because no SSTI sink was evidenced; searchsploit because no CVE/product-version route was evidenced; radare2/angr because no native binary artifact was involved.
- Missing: none.
- Decision summary: This is a web OAuth logic chain; direct requests provide the shortest reproducible proof.

# Blocker or Solve

Solved. The replay creates a fresh DreamHack request-bin host, sets client-app's callback base to that host, has the admin bot authorize through the normal OAuth login form, captures the admin authorization code from the request bin, redeems it through a fresh client-app session by omitting `state`, and calls the protected resource API as `admin`.

The remote replay succeeded at `2026-06-30T17:43:08Z`. The raw replay log contains the flag and the generated replay summary redacts it. The flag hash recorded by the replay is `0567c3e6a0cbcd16377a919d08cbc8e69f02cc94e55efc6f03e58920326a762f`.

# Evidence

- `evidence/baseline_client_root.http`
- `evidence/baseline_auth_root.http`
- `evidence/baseline_bot_report.http`
- `evidence/client_login_redirect.headers`
- `evidence/requestbin_create_probe.http`
- `evidence/replay_20260630T174308Z.log`
- `evidence/replay_20260630T174308Z.summary.md`
- `evidence/replay_20260630T174308Z.sanitize_check.md`
