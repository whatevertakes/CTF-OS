# Cloud exploit-first playbook

## 1. Fast recon budget

Use only challenge-declared accounts/projects/tenants, endpoints, and temporary credentials. Budget three observations: (1) identify the supplied identity/config and trust boundary; (2) issue one baseline scoped API/policy query; (3) test one highest-value permission/service chain. Then execute the leading scoped exploit.

## 2. Highest-value exploit hypotheses

Prefer direct object access, assume-role/impersonation, signed URL/token misuse, workload identity, registry/OCI secret, CI/CD trust, Kubernetes/RBAC escalation, or function/workload execution when concrete configuration or API evidence supports it.

## 3. Cheapest decisive experiments

Evaluate one effective permission, fetch one likely object, simulate one role binding, inspect one referenced image/config, assume one declared role, or perform one reversible scoped action. Record required mutations in the branch ledger.

## 4. Immediate PoC criteria

A minimal provider CLI command or script that proves the permission chain, accesses the flag-bearing resource, or executes the scoped action is a working PoC. Do not build a full IAM graph unless the chain requires it.

## 5. Remote transition criteria

Challenge cloud APIs are the declared remote. Use them as soon as the permission hypothesis is plausible; do not delay for a full static policy audit. Credentials remain worker-private and redacted.

## 6. Kill conditions

Kill when the effective permission is denied for the hypothesized reason, the resource/trust edge is absent, or one alternate decisive call does not improve proximity. Replace identity, object, workload, or supply-chain mechanism explicitly.

## 7. Common research-drift traps

Do not enumerate every service/resource, map the full IAM/RBAC graph after a viable chain exists, run broad scanners by default, write a cloud posture report, generalize automation, or investigate unrelated accounts. Never query ambient/cloud metadata or use personal credentials.

## 8. Flag fast path

Publish the proven permission/execution primitive or working command first. Preserve the scoped API receipt, mutation ledger entry, minimal exploit, and exact flag output; recommend submission without waiting for replay.
