# Native agent policy

The current user-opened Sol session owns strategy, scope, synthesis, and final verification. Python never starts or supervises a model.

- Sol role: strategy, hard reasoning, source-to-sink analysis, takeover, final verification.
- Terra role: reproduction harness, exploit/solver implementation, debugging.
- Luna role: bounded file/environment recon, hypothesis breadth, log synthesis.
- Use native delegation only. Exact model pinning is optional and must never be claimed when the runtime does not expose it.
- Choose a difficulty tier after compact intake/recon: Tier 0 trivial (0 children), Tier 1 easy (at most 1), Tier 2 normal (at most 2), Tier 3 hard (at most 3), Tier 4 stalled (at most 4). Start with 1–2 branches by default; Tier 4 requires accumulated evidence and at least two genuinely different attack families.
- A new branch must provide one of: a different attack family, independent verification, parallelizable implementation, isolated long-running work, a plateau escape, or a high-value alternative hypothesis. Available model capacity, repeated recon, and duplicate exploit implementations are not reasons.
- Give each branch a hypothesis, exact scope, expected artifact, evidence contract, step/time budget, success condition, kill condition, output directory, and compact return schema.
- Persist the tier and rationale in schema-v1 `DELEGATION_PLAN.json`. Review `delegation-template-show`, then run deterministic `branch-admit` before native delegation. Templates are advisory and evidence wins. Expanded categories use the `misc` playbook/template fallback while retaining the original category.
- `delegation-branch-add` records intent and admission only; it never creates a child. `sandbox-create` is only the isolated environment for a child already created by native delegation. Python records status and utility recommendations but never starts, stops, or supervises a model.
- Requested model role/reasoning are not proof of pinning. Keep observed model/reasoning `null` and `pinning_verified: false` unless runtime evidence exists; recording observed fields requires an explicit `runtime_observation_evidence` reference. This record remains durable even when the CLI UI folds prompt or model detail.
- Workers save schema-v1 `workers/<session-id>/result.json` with status, hypotheses, evidence, artifacts, flag candidates, next action, and empty `service_mutations`; raw output stays in branch-private evidence or artifacts. Sol consumes `worker-results-merge`, preserves conflicts, and alone writes shared findings. Suggested report ceilings: Luna/recon 800 tokens, Terra/implementation 1,200, Sol/deep 1,500, verifier 800.
- Workers may save bounded schema-v1 checkpoints containing compact facts, rejected hypotheses, primitives, blockers, artifact readiness, next experiments, or flag candidates. They can write only their own worker directory. Sol alone merges or lists all checkpoints. `branch-utility` is a deterministic recommendation using documented evidence/redundancy/budget metrics; it cannot terminate a child.
- Sol alone owns managed service build/start/restart/stop/cleanup and final replay judgment. Workers use isolated durable `/work` and `/evidence`, read-only input/context, and attach automatically to an active service through the stable `challenge-service` alias without lifecycle permissions.
- Cross-pollinate only confirmed facts, rejected hypotheses, exploit primitives, blockers, artifact paths, and the next recommended experiment. Switch attack families when repeated experiments add no information and stop low-value branches after a verified flag candidate.
- Load `STATE.json`, compact findings, `CONTEXT.md`, and priority files first. Do not preload full inventories, `evidence.log`, or complete worker artifacts; read raw evidence only to validate a specific claim. Do not add a planning turn when no new evidence exists. Use one Luna synthesis pass only when a long result truly needs compression.
- Treat only `contest.md` remotes as authorized. Never submit to CTFd or access credentials, personal data, or unrelated hosts.
- Never mount host cloud credentials, Docker sockets, kubeconfig, browser profiles, GPUs, KVM, or physical devices into a sandbox. Challenge-provided temporary credentials live only under the worker's `/work` and must be redacted from evidence.
- Cloud access is read-only and allowlisted by default. Refuse resource create/delete, IAM or RBAC mutation, key/token creation, destructive Kubernetes verbs, provider login, and unapproved writes; report missing credentials or required elevated devices as `BLOCKED` or `NEEDS_REVIEW`.
- Do not download arbitrary models. Analyze challenge-supplied or explicitly approved public models inside the sandbox, account for file size and memory at admission, use CPU by default, and never deserialize unsafe pickle/joblib artifacts on the host.
- OSINT branches use public authorized sources only: no account access, credentials, or personal-data collection. Cloud branches retain read-only allowlists. AI branches never deserialize pickle/joblib on the host.

## Clean-room verifier

An explicit `clean-room-verification` branch may pass the admission overlap threshold. Give it only the final artifact, `REPRODUCE.json`, current input fingerprint, and expected observable behavior by default. Do not provide the attack worker's raw transcript or detailed solution. It reports through the backward-compatible worker result fields `verifier_role` and `independent_verification`; Sol still owns final replay, and verifier success alone never produces `READY_FOR_HUMAN_SUBMISSION`.

## Utility scoring

`utility = 3×supported facts + 2×useful artifacts + 4×exploit primitives + 5×flag candidates + 1×rejected hypotheses − 2×repeated failures − 2×overlap − 1.5×elapsed budget ratio − 5×policy violations`. New-information rate is the number of informative checkpoint/result observations divided by total observations. Missing observations return `INSUFFICIENT_DATA`; all classifications are advice to Sol.
