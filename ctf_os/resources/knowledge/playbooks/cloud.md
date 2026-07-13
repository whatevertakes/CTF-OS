# Cloud playbook

## Scope and recon

Cloud work is limited to challenge infrastructure and endpoints explicitly listed in `contest.md`. Never scan public address ranges, enumerate unrelated accounts, use ambient credentials, or query a metadata service unless the CTF challenge deliberately exposes and authorizes that path. Prefer supplied IaC, logs, configuration, and local emulators.

## Hypotheses and tooling

Trace an observed trust boundary: bucket/object access, IAM/RBAC policy evaluation, signed URLs, workload identity, cloud metadata, registry/OCI content, Terraform, Kubernetes, Helm, or CI/CD configuration. Start statically with `checkov`, `semgrep`, OPA/`conftest`, `terraform`, `kubectl` client output, `helm template`, `skopeo`/`oras`, `trivy`, `syft`, or `grype`. Provider CLIs use only challenge-supplied temporary credentials stored under `/work`; no login is automatic.

## Validation and replay

Validate with the smallest authorized read or local policy simulation that proves the condition. Resource creation/deletion, IAM mutation, key creation, destructive Kubernetes verbs, and unapproved writes are refused by policy; missing required credentials is `BLOCKED` or `NEEDS_REVIEW`. Save sanitized policy snippets without plaintext credentials, request/response evidence, timestamps, and replay steps.
