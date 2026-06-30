# Cloud And Container Reference Digest

## Trusted Sources

- `ref:kctf`: CTF infrastructure and Kubernetes challenge reference.
- `ref:kubernetes_goat`: Kubernetes security lab pattern reference.
- `ref:trivy`: image, config, and dependency scanning reference.
- `ref:hacktricks`: cloud/container checklist reference.

## CTF-Relevant Patterns

- Freeze authorization boundary, configs, credentials handling, manifests, images, logs, local endpoints, and secret-handling rules.
- For containers, hash images/layers and record users, capabilities, mounts, sockets, environment, entrypoints, seccomp, AppArmor, and Kubernetes context.
- Reproduce runtime behavior locally before namespace, cgroup, socket, or host-interface hypotheses.
- Preserve sanitized command transcripts and never store real secrets in notes.

## CWE/CVE Mapping

- Map exposed secrets, metadata access, IAM/policy weakness, container escape, and misconfiguration only with config/runtime evidence.
- Use CVEs only for exact image package/kernel/component versions and challenge-owned scope.

## Canonical Papers And Deep Dives

- Kubernetes security and container isolation references are useful for modeling boundaries and escape surfaces.

## When To Use

- Use for cloud configs, identity policies, metadata services, Docker images, Kubernetes manifests, namespaces, and local container services.

## When Not To Use

- Do not interact with infrastructure outside the challenge authorization boundary.

## Source Anchors

- `idx:cloud-container:kctf:overview`
- `idx:cloud-container:kubernetes_goat:overview`
- `idx:cloud-container:trivy:overview`
- `idx:cloud-container:hacktricks:overview`
