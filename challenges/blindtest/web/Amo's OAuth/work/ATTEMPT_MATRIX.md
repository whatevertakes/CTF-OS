# Attempt Matrix

| Family | Result | Evidence |
| --- | --- | --- |
| Source review | Found non-exact OAuth redirect validation, globally mutable client URLs, bot-admin login flow, and a client callback state check that accepts an omitted state when the session has no `state` key. | `deploy/*/server.js`, `deploy/bot/bot.js` |
| Direct local evidence | Baseline responses confirmed the public ports map to client-app, auth-server, and bot. | `evidence/baseline_*.http` |
| DreamHack request bin | Confirmed fresh request-bin hosts are creatable and observable through `/_host/create`, `/_log/<host>`, and `/_data/<request_id>`. | `evidence/requestbin_create_probe.http` |
| Browser/MCP | Skipped because source plus direct HTTP requests fully described the flow; no client-only behavior was needed. | Tool routing notes |
| Burp proxy | Skipped to avoid unnecessary proxying of low-volume reproducible HTTP requests; `requests` and `curl` were sufficient. | Tool routing notes |
