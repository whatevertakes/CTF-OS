# Cloud playbook

## Scope and recon

Cloud work is limited to challenge infrastructure, accounts/projects/tenants, credentials, and endpoints explicitly declared for the selected challenge. Never use ambient/personal credentials, enumerate unrelated accounts, or query host/cloud metadata outside the challenge target. Challenge-provided temporary credentials are normal solver inputs.

## Hypotheses and tooling

Trace an observed trust boundary: bucket/object access, IAM/RBAC policy evaluation, signed URLs, workload identity, cloud metadata, registry/OCI content, Terraform, Kubernetes, Helm, or CI/CD configuration. Start statically with `checkov`, `semgrep`, OPA/`conftest`, `terraform`, `kubectl` client output, `helm template`, `skopeo`/`oras`, `trivy`, `syft`, or `grype`. Provider CLIs use only challenge-supplied temporary credentials stored under `/work`; no login is automatic.

## Validation and replay

Pursue the shortest authorized exploit path. Account enumeration, assume-role/service-account impersonation, object writes, function/workload/pod/job creation, and limited IAM/RBAC mutation are allowed when required inside the declared challenge scope. Log every mutation in the branch ledger, redact credentials, and avoid unbounded destructive cleanup. A valid scoped flag receipt is submission-ready without waiting for two clean replays.
