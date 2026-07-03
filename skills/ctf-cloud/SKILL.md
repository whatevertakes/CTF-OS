purpose: Analyze cloud CTF artifacts, IAM-like logic, service configs, metadata, and deployment paths within owned scope.
when_to_use:
- The challenge includes cloud configuration, identity policy, metadata, serverless, storage, or Kubernetes-adjacent clues.
when_not_to_use:
- The task would interact with real third-party infrastructure outside the challenge authorization.
inputs:
- Config files, policies, logs, manifests, local lab endpoints, or challenge-provided credentials.
outputs:
- Scope statement, config findings, command transcript, and next-step routing.
dependencies:
- `skills/ctf-triage/SKILL.md`
- kCTF or provider docs as references only.
- Optional kubectl, trivy, syft, grype, crane, and skopeo references when cloud
  evidence includes owned clusters, container images, registries, or manifests.
reference_digest:
- `docs/reference-digests/cloud-container.md`
evidence produced:
- Local configs, hashes, command outputs, and proof logs.
failure/blocker classes:
- Unclear authorization boundary.
- Missing local or owned target.
- Credentials or secrets that should not be stored.
future agent consumers:
- Cloud solver.
- Container solver.
- Hybrid-chain solver.
workflow:
- Freeze authorization boundary, challenge-provided credentials, configs, endpoints, logs, and secret-handling rules.
- Do not store real secrets in notes or public summaries; sanitize transcripts.
- Analyze identity policy, metadata, storage, serverless, logs, and deployment paths independently.
- Use trivy, syft, grype, crane, or skopeo only for challenge-owned image or
  registry artifacts; route deeper runtime work to `ctf-container`.
- Use kubectl only for local, challenge-owned, or explicitly authorized cluster
  contexts, and preserve sanitized transcripts.
- Use provider CLIs only in owned challenge scope and record exact commands.
- Route image, pod, or namespace artifacts to `ctf-container`; route web/API behavior to `ctf-web`.
first_commands:
- `find dist -maxdepth 3 -type f -print`
- `sha256sum dist/*`
- `jq . <config.json>` or `yq . <config.yaml>` when applicable.
- `kubectl version --client=true` before any scoped cluster command.
- `crane digest <image>` or `skopeo inspect docker://<image>` for scoped registry artifacts.
- `trivy image <image>`, `syft <image>`, or `grype <image>` when image evidence is in scope.
- `python3 tools/proof_validate.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
