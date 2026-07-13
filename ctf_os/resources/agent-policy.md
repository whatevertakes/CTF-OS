# Native agent policy

The current user-opened Sol session owns strategy, scope, synthesis, and final verification. Python never starts or supervises a model.

- Sol role: strategy, hard reasoning, source-to-sink analysis, takeover, final verification.
- Terra role: reproduction harness, exploit/solver implementation, debugging.
- Luna role: bounded file/environment recon, hypothesis breadth, log synthesis.
- Use native delegation only. Exact model pinning is optional and must never be claimed when the runtime does not expose it.
- Choose a difficulty tier after compact intake/recon: Tier 0 trivial (0 children), Tier 1 easy (at most 1), Tier 2 normal (at most 2), Tier 3 hard (at most 3), Tier 4 stalled (at most 4). Start with 1–2 branches by default; Tier 4 requires accumulated evidence and at least two genuinely different attack families.
- A new branch must provide one of: a different attack family, independent verification, parallelizable implementation, isolated long-running work, a plateau escape, or a high-value alternative hypothesis. Available model capacity, repeated recon, and duplicate exploit implementations are not reasons.
- Give each branch a hypothesis, exact scope, expected artifact, evidence contract, step/time budget, success condition, kill condition, output directory, and compact return schema.
- Workers return only `branch_id`, `status`, `confirmed_facts`, `rejected_hypotheses`, `artifacts`, `commands_of_interest`, `next_action`, and `confidence`. Raw output stays in `evidence.log` or branch artifacts. Suggested report ceilings: Luna/recon 800 tokens, Terra/implementation 1,200, Sol/deep 1,500, verifier 800.
- Cross-pollinate only confirmed facts, rejected hypotheses, exploit primitives, blockers, artifact paths, and the next recommended experiment. Switch attack families when repeated experiments add no information and stop low-value branches after a verified flag candidate.
- Load `STATE.json`, compact findings, `CONTEXT.md`, and priority files first. Do not preload full inventories, `evidence.log`, or complete worker artifacts; read raw evidence only to validate a specific claim. Do not add a planning turn when no new evidence exists. Use one Luna synthesis pass only when a long result truly needs compression.
- Treat only `contest.md` remotes as authorized. Never submit to CTFd or access credentials, personal data, or unrelated hosts.
