# Cloud playbook

## Scope and recon

Cloud work is limited to challenge infrastructure and endpoints explicitly listed in `contest.md`. Never scan public address ranges, enumerate unrelated accounts, use ambient credentials, or query a metadata service unless the CTF challenge deliberately exposes and authorizes that path. Prefer supplied IaC, logs, configuration, and local emulators.

## Hypotheses and tooling

Trace an observed trust boundary: bucket/object access, IAM policy evaluation, signed URLs, workload identity, JWT/OIDC claims, configuration leaks, logging, or an application SSRF path. Use read-only, least-privilege challenge requests with `curl` or provider CLIs configured only for supplied test credentials. Keep request volume low and each probe tied to a documented hypothesis.

## Validation and replay

Validate with the smallest authorized read or policy simulation that proves the condition; do not alter cloud resources. Save sanitized policy snippets, request/response evidence, timestamps, and replay steps. Report inaccessible or denied paths as findings, then pivot without expanding scope.
