# Web attack playbook

## 1. Fast recon budget

Use only the declared application. Budget three observations: (1) entrypoint plus the highest-value dataflow boundary in supplied source or visible route; (2) one baseline request preserving cookies/redirects; (3) one highest-value payload or source-to-sink test. Then choose an exploit chain; do not enumerate the application.

## 2. Highest-value exploit hypotheses

Choose at most three reachable chains involving auth/session bypass, injection, template execution, traversal/file read, unsafe upload, SSRF/OAST, token confusion, parser/serialization behavior, or business logic. Track only the auth/session steps required by that chain.

## 3. Cheapest decisive experiments

Send one controlled comparison request that can prove or kill the sink/bypass: a quote/operator differential, template expression, traversal target, signed-token mutation, callback token, or role/ownership swap. Prefer a single reversible request over crawling.

## 4. Immediate PoC criteria

A minimal `curl`, raw request, or short Python client that proves read, bypass, callback, execution, or flag-relevant state change is a working PoC. Save the exact request/response rather than a taxonomy report.

## 5. Remote transition criteria

If source/local behavior makes the chain plausible, test the declared remote immediately. Remote-only auth, bot, OAST, session, and deployment behavior are part of the decisive experiment, not a final ceremony.

## 6. Kill conditions

Kill when the input cannot reach the suspected sink/boundary, the baseline differential disproves the assumption, or one payload-family change still produces no exploit-relevant effect. Then replace the mechanism, not merely the payload spelling.

## 7. Common research-drift traps

Do not enumerate every endpoint, audit all source after one reachable sink exists, build a vulnerability taxonomy, fuzz unrelated parameters, map the whole framework, or keep exploring bugs while a viable exploit chain is alive.

## 8. Flag fast path

Publish the bypass/read/execution primitive or working request first. Execute the smallest declared-remote chain, preserve the exact redacted receipt and exploit client, and surface the flag immediately.
