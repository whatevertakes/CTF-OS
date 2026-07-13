---
name: ctf-solve
description: Deep-solve exactly one authorized CTF challenge with the current Sol session as lead and an adaptive native-agent swarm/race. Use for requests such as "1번 문제 풀어라", "pwn/NBB 풀어라", "NBB deep solve", or "이 문제 swarm으로 풀어라" after intake has been completed.
---

# CTF solve swarm

The current user-opened Sol session is the sole lead orchestrator. Never run Codex from Python or a shell. Never submit a flag.

## Load and select

1. Read root `AGENTS.md`, `contest.md`, `ctf_os/resources/agent-policy.md`, and the matching `ctf_os/resources/knowledge/playbooks/<playbook_category>.md` returned by intake (expanded categories safely use `misc.md`).
2. Run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<name>'`.
3. Stop on a stale/missing intake index, BLOCKED context, or ambiguous selector. Show candidates instead of choosing one.
4. Start with the compact prepare result, `CONTEXT.md`, `STATE.json`, compact `FINDINGS.md`, and priority files. Treat `read_on_demand`, the full file inventory, `evidence.log`, and worker artifacts as indexes: open only the item needed to validate a specific claim. Never preload raw logs.

## Adaptive race

Choose a difficulty tier after compact initial analysis. Use native delegation only when a branch condition below is met; the current Sol remains the attacker and integrator. If exact model selection exists, prefer Luna for broad/cheap recon, Terra for harnesses and implementation, and Sol for hard reasoning/takeover; otherwise assign roles without claiming model pinning.

- Tier 0 — trivial: 0 children; Sol handles obvious encoding, metadata, constants, and simple source bugs.
- Tier 1 — easy: at most 1 child; delegate only the needed recon or implementation task.
- Tier 2 — normal: at most 2 children; non-overlapping recon and implementation while Sol owns strategy.
- Tier 3 — hard: at most three non-overlapping children; static/deep reasoning, reproduction/exploit, and a different attack family.
- Tier 4 — stalled: at most 4 children, only after useful evidence exists and at least two attack families are live; Sol takeover is allowed.

Start with 1–2 branches by default and expand only when evidence justifies it. Create a branch only for a different attack family, independent verification, parallelizable implementation, isolated long-running work, a plateau, or a high-value alternative hypothesis. Never create one merely because a model is available, to repeat recon, or to rewrite the same exploit.

- Phase 1 recon: define distinct hypotheses and explicit file/remote scope. Typical branches are static attack-surface analysis, local reproduction/harness, and an independent alternate attack family.
- Phase 2 selection: compare evidence, failed hypotheses, experiment cost, expected success, duplication, and remote risk. Continue two exploit branches when confidence is low.
- Phase 3 exploit race: assign genuinely different primitives or implementation paths. Do not duplicate the same solver. Record failures too.
- Phase 4 cross-pollination: append supported/rejected/inconclusive results with `record-finding`; send useful discoveries to active branches, terminate low-value work, and let the lead Sol take over stalled high-value analysis.
- Phase 5 verification: rerun from clean conditions. Use an independent branch or lead verification to distinguish the real challenge flag from examples/placeholders.

Every branch assignment must state: `hypothesis`, exact `scope`, `expected_artifact`, `evidence_contract`, maximum steps/time, `success_condition`, `kill_condition`, and output directory. Each worker owns only `output/<contest>/<category>/<challenge>/workers/<branch-id>/` and its sandbox. They must not access another challenge, undeclared network target, host credentials, or user files.

Workers return this compact shape, never a raw transcript:

```json
{
  "branch_id": "heap-uaf",
  "status": "promising",
  "confirmed_facts": [],
  "rejected_hypotheses": [],
  "artifacts": [],
  "commands_of_interest": [],
  "next_action": "",
  "confidence": 0.0
}
```

Keep reports within roughly 800 tokens for Luna recon/verifiers, 1,200 for Terra implementation, and 1,500 for a Sol deep branch. Raw command output belongs only in `evidence.log` or a branch artifact. Cross-pollinate only confirmed facts, rejected hypotheses, exploit primitives, blockers, useful artifact paths, and the next recommended experiment. If no new evidence exists, do not spend another Sol turn restating the plan; use one Luna synthesis pass only when a long result truly needs compression.

## Sandbox and evidence

Use the recommended image/resource profile unless evidence requires a change. Check admission with `sandbox-status`, then create an attempt with `sandbox-create '<selector>' --contest '<name>' --branch '<id>'`. Execute direct argv with `sandbox-exec '<.../sandbox.json>' --timeout N -- <command>`. Input is `/challenge` read-only; only `/work` and `/artifacts` are writable. Commands do not repeatedly export `/artifacts`; call `sandbox-export '<.../sandbox.json>'` after a valuable artifact/flag, and always call `sandbox-cleanup` for final export and removal.

For an intake-approved Dockerfile/Compose challenge, call `service-plan`, `service-build`, and `service-start`, then create the analysis sandbox with the internal `--service` path. The service and sandbox share only the challenge's internal `ctf-os-net-*` network; organizer remotes remain a separate sandbox path. Never override a `NEEDS_REVIEW` plan blindly. Call `service-cleanup` after the attempt.

Record material claims with `record-finding '<selector>' --branch '<id>' --status supported|rejected|inconclusive --summary '...' --evidence '...'`. Keep the final solver under `exploit/`. Before verification, write `REPRODUCE.json` with schema version 1, direct `argv` (normally using `/artifacts/exploit/...`), current input fingerprint, recommended image/resource profile, service requirement, expected flag pattern, and a separate `remote_argv` when organizer reproduction needs a different target. Do not put shell pipelines or host commands in the contract.

Call `replay '<selector>' --contest '<name>'`. It validates the fingerprint, starts any required local service, stages the solver into two independent clean sandboxes, executes direct argv, extracts and pattern-checks a common candidate, performs a distinct authorized-remote replay when required, verifies actual remote firewall observations, and cleans every sandbox/service. Only its distinct recorded receipts may produce `READY_FOR_HUMAN_SUBMISSION`; a flag-looking string or boolean assertion alone remains `VERIFICATION_REQUIRED`. `reproduce.sh` is generated as a thin wrapper around this replay tool and never runs the exploit on the host.

Return: problem, state, exact verified flag candidate if ready, local/remote/independent/pattern checks, reproduce path, core vulnerability, and the warning that submission is manual. Never claim SOLVED when verification is incomplete.
