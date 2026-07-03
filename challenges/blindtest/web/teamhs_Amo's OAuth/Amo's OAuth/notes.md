en# Challenge Notes

## Summary

- Event: blindtest
- Category: web
- Name: Amo's OAuth
- Status: solved
- Description: Amo's first OAuth test app.
- Remote endpoints: client `http://host3.dreamhack.games:10841/`, auth `http://host3.dreamhack.games:13635/`, bot `http://host3.dreamhack.games:10480/`.

## Artifacts

- The original source handout is preserved under `dist/`; its complete hash manifest is `work/handout-sha256.txt`.
- `dist/docker-compose.yml` defines client, auth, resource, and bot services.
- The supplied directory name is not a lowercase hyphenated slug, but it was already present at the exact user-assigned path. Intake was not run with `--force`.

## Observations

- Public port roles from source and assignment: 10841/client-app:3000, 13635/auth-server:4000, 10480/bot:8000. The resource server is internal on port 5000.
- The resource server returns the flag only when the verified HS256 token has `sub == "admin"`.
- The bot signs in as `administrator` using a secret environment password.
- Client OAuth endpoints use process-global mutable auth-server and client-base URLs, shared across all sessions.
- The OAuth callback exchanges codes against the fixed internal auth server, while browser authorization uses the mutable URL.
- Auth redirect validation accepts `client-app` and any hostname ending in `.dreamhack.games`.
- A request from the public client endpoint follows the non-private branch: `/login` sends constant `state=_prod` but stores a random value plus `_prod`, so ordinary external OAuth callbacks cannot validate.
- A fresh session calling `/callback?code=<code>` with the `state` parameter omitted passes because both `req.query.state` and `req.session.state` are `undefined`.
- Dreamhack's official Request Bin generates hostnames under `*.request.dreamhack.games`, satisfying the auth server's redirect allowlist and preserving the bot's callback query.
- The bot callback evidence showed a 24-character code, a state ending `_local`, HeadlessChrome, and an internal `http://auth-server:4000/` referer.

## Hypotheses

- Proven: mutable OAuth configuration can direct the admin bot's code to an official Request Bin under the permitted domain suffix.
- Proven: the missing-state callback accepts the captured admin code in a fresh attacker session, where the client exchanges it with its internal secret.
- Proven: `/call-api` then sends the server-side admin access token to the internal resource server and returns the flag.
- Falsified: normal external `/login` is usable; its `_prod` state does not match the random session state.
- Falsified: default `clientsecret` or literal `[REDACTED]` is the deployed client secret; both returned `invalid_client` with a disposable amo code.
- Falsified/deprioritized: direct JWT forgery, EJS XSS, and generic template/CVE scanning; source pins HS256 and escapes all observed render contexts.

## Attempts

- Source route/trust inventory identified client, auth, resource, and bot roles.
- `curl -i` baselines confirmed 10841=client, 13635=auth, and 10480=bot.
- External state behavior was reproduced after setting public auth/client URLs: `Location` contained `state=_prod`.
- The known amo credentials created a disposable authorization code. Calling `/callback?code=<code>` without a cookie or `state` established an amo token session, proving the state bypass independently of the bot.
- The final chain used `GET https://tools.dreamhack.games/_host/create`, set `http://auth-server:4000` and the generated Request Bin as process-global URLs, and submitted `url=http://client-app:3000/login` to the bot.
- `work/solve.py` polls the bin for `/callback`, verifies the `_local` state suffix, redeems only the captured code without state, calls `/call-api`, and requires a flag-shaped response.
- `python3 tools/replay_runner.py --allow-remote-live "challenges/blindtest/web/Amo's OAuth"` reproduced the entire chain with a fresh bin/code and exit 0.
- See `work/ATTEMPT_MATRIX.md` for tested hypothesis families.
- See `work/MUTATION_LEDGER.md` for state-changing requests.

## Tool Routing Decision

- Primary tools used: supplied source, `curl`, Python standard-library replay, official Dreamhack Request Bin, challenge admin bot.
- Considered: source inspection, `curl`, Python HTTP/cookie automation, local Docker Compose, Playwright, Burp, tplmap, searchsploit.
- Used: `find`, `sha256sum`, `file`, source inspection, low-volume `curl`, official Request Bin API, `urllib`, `CookieJar`, challenge bot browser.
- Skipped: standalone Playwright because the supplied bot already executed and attested the required browser flow; Burp because source plus saved direct request/response pairs exposed the complete state transition; tplmap because no template-render injection sink existed; searchsploit because no product-version CVE hypothesis was needed.
- Missing: Docker Compose plugin (`docker compose` is unavailable). This did not block the remote source-backed proof.
- Decision summary: the source exposed a narrow OAuth logic chain. Direct requests and the official Request Bin produced clearer reproducible evidence than proxying or generic scanning.

## Blocker or Solve

- Current state: solved with a fresh live remote admin-code capture and internal API flag response.
- Final command: `python3 tools/replay_runner.py --allow-remote-live "challenges/blindtest/web/Amo's OAuth"`

## Evidence

- `evidence/requestbin_admin_callback.summary.md`: sanitized admin bot callback provenance; the consumed raw code remains local under `work/`.
- `evidence/replay_20260630T174020Z.log`: official replay-runner raw proof containing the flag.
- `evidence/replay_20260630T174020Z.summary.md`: replay summary with the flag redacted, exit 0, `_local` bot state, and remote liveness.
- `evidence/replay_sanitize_check.summary.md`: explicit `report_sanitize.py --check` output for the sensitive replay.
- `evidence/proof_validate.txt`: final proof-validation transcript.
