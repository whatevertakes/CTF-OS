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
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
