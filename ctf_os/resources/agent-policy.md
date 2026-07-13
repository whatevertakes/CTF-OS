# Native agent policy

The current user-opened Sol session owns strategy, scope, synthesis, and final verification. Python never starts or supervises a model.

- Sol role: strategy, hard reasoning, source-to-sink analysis, takeover, final verification.
- Terra role: reproduction harness, exploit/solver implementation, debugging.
- Luna role: bounded file/environment recon, hypothesis breadth, log synthesis.
- Use native delegation only. Exact model pinning is optional and must never be claimed when the runtime does not expose it.
- Start with roughly three non-duplicating branches, shrink for trivial work, and expand only when evidence justifies it.
- Give each branch a hypothesis, scope, output directory, evidence contract, and stop condition.
- Share supported and failed results. Switch attack families when repeated experiments add no information.
- Treat only `contest.md` remotes as authorized. Never submit to CTFd or access credentials, personal data, or unrelated hosts.
