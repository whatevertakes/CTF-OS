# Web playbook

## Scope and recon

Connect only to the URL in `contest.md`; do not crawl unrelated hosts, enumerate broad networks, or use credentials outside the challenge. Capture a baseline response, headers, redirects, cookies, routes linked by the application, and supplied source. Build a request ledger with method, path, parameters, status, and body digest.

## Hypotheses and tooling

Start from observed data flow: authorization boundaries, server-side template use, database queries, file handling, redirects, and token validation. Use `curl` or an intercepting proxy with small, reversible probes. Test one hypothesis at a time for SQL injection, SSTI, traversal, SSRF, JWT/OIDC handling, or deserialization only where the challenge exposes a relevant input.

## Validation and replay

Confirm impact with the smallest authorized request and a clean baseline comparison. Save redacted request/response pairs, source locations, and reproduction steps under `/artifacts`; never copy browser profiles, API keys, or personal secrets. If a probe only changes an error, record that observation and shift to the next evidenced hypothesis.
