# Mutation Ledger

| Time (UTC) | Target | Action | Purpose | Evidence |
| --- | --- | --- | --- | --- |
| 2026-06-30T17:40Z | `tools.dreamhack.games` | `GET /_host/create` | Verified a fresh DreamHack request-bin can be created for an allowed `.dreamhack.games` redirect host. | `evidence/requestbin_create_probe.http` |
| 2026-06-30T17:43Z | `host3.dreamhack.games:10841` | `POST /set-auth-server` with `http://auth-server:4000` | Ensure the bot's internal client-app login uses the internal auth server. | `evidence/replay_20260630T174308Z.summary.md` |
| 2026-06-30T17:43Z | `host3.dreamhack.games:10841` | `POST /set-client-url` with `https://zpkqfmb.request.dreamhack.games` | Route the admin authorization code to a readable DreamHack request bin. | `evidence/replay_20260630T174308Z.summary.md` |
| 2026-06-30T17:43Z | `host3.dreamhack.games:10480` | `POST /report` with `http://client-app:3000/login` | Trigger the admin bot to complete the OAuth authorization flow. | `evidence/replay_20260630T174308Z.summary.md` |
| 2026-06-30T17:43Z | `host3.dreamhack.games:10841` | `GET /callback?code=<admin-code>` with no `state` parameter in a fresh session | Redeem the captured admin code through client-app's stored client secret and unset-state check. | `evidence/replay_20260630T174308Z.summary.md` |
| 2026-06-30T17:43Z | `host3.dreamhack.games:10841` | `GET /call-api` | Use the admin access token stored in the fresh session to call the protected internal resource API. | `evidence/replay_20260630T174308Z.summary.md` |
