---
name: ctf-solve
description: Deep-solve exactly one authorized CTF challenge with the current Sol session as lead and an adaptive native-agent swarm/race. Use for requests such as "1번 문제 풀어라", "pwn/NBB 풀어라", "NBB deep solve", or "이 문제 swarm으로 풀어라" after intake has been completed.
---

# CTF solve swarm

The current user-opened Sol session is the sole lead orchestrator. Never run Codex from Python or a shell. Never submit a flag.

## Load and select

1. Read root `AGENTS.md`, `contest.md`, the current `output/<contest>/TRIAGE.md`, `ctf_os/resources/agent-policy.md`, and the matching `ctf_os/resources/knowledge/playbooks/<playbook_category>.md` returned by intake (expanded categories safely use `misc.md`).
2. Run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<name>'`.
3. Stop on a stale/missing intake or Challenge Triage index, BLOCKED context, or ambiguous selector. Show candidates instead of choosing one.
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
- Phase 4 cross-pollination: require each worker to save its branch-private structured result, then let Sol merge and judge those results. Sol alone appends accepted claims with `record-finding`, sends useful discoveries to active branches, terminates low-value work, and takes over stalled high-value analysis.
- Phase 5 verification: rerun from clean conditions. Use an independent branch or lead verification to distinguish the real challenge flag from examples/placeholders.

Every branch assignment must state: `hypothesis`, exact `scope`, `expected_artifact`, `evidence_contract`, maximum steps/time, `success_condition`, `kill_condition`, and output directory. Each worker owns only `output/<contest>/<category>/<challenge>/workers/<branch-id>/` and its sandbox. They must not access another challenge, undeclared network target, host credentials, or user files.

Workers save `workers/<branch-id>/result.json` and return this compact shape, never a raw transcript:

```json
{
  "schema_version": 1,
  "session_id": "heap-uaf",
  "parent_session_id": "sol-main",
  "challenge_id": "abc123",
  "input_fingerprint": "current prepared source fingerprint",
  "role": "exploit-implementation",
  "status": "SUPPORTED",
  "summary": "Confirmed a reusable UAF primitive",
  "hypotheses": [],
  "artifacts": ["work/poc.py"],
  "flag_candidates": [],
  "recommended_next_step": "Integrate the primitive in the parent exploit",
  "service_mutations": [],
  "policy_violations": [],
  "started_at": "2026-07-13T00:00:00Z",
  "finished_at": "2026-07-13T00:05:00Z"
}
```

Use only `SUPPORTED`, `REFUTED`, `PARTIAL`, `INCONCLUSIVE`, `ERROR`, or `FLAG_CANDIDATE`. Keep `service_mutations` empty. Submit with `worker-result-save`, then have Sol call `worker-results-merge`; preserve conflicting observations for Sol instead of resolving them in a worker.

Keep reports within roughly 800 tokens for Luna recon/verifiers, 1,200 for Terra implementation, and 1,500 for a Sol deep branch. Raw command output belongs only in `evidence.log` or a branch artifact. Cross-pollinate only confirmed facts, rejected hypotheses, exploit primitives, blockers, useful artifact paths, and the next recommended experiment. If no new evidence exists, do not spend another Sol turn restating the plan; use one Luna synthesis pass only when a long result truly needs compression.

## Sandbox and evidence

Use the recommended image/resource profile unless evidence requires a change. Check admission with `sandbox-status`, then have Sol create an attempt with `sandbox-create '<selector>' --contest '<name>' --branch '<id>' --session-role child --session-id '<id>'`. Execute direct argv with the same child identity. Input and `/context` are read-only; `/work`, `/evidence`, and `/artifacts` are bounded worker-private filesystems. `worker-result-save`, explicit export, and cleanup atomically retain their safe regular files under the worker directory. A worker may operate only its own sandbox. Preserve that directory until Sol has collected and merged the result.

For an intake-approved Dockerfile/Compose challenge, Sol calls `service-plan`, `service-build`, and `service-start` as `sol-main`. Creating a worker then automatically attaches an already-running managed service, injects the stable `challenge-service` endpoint and attach-only context, restricts worker egress to that service, and probes connectivity. Keep `--service` only when attachment must be required explicitly. Never create a replacement service after attachment failure. Child sessions may call only service status/logs/inspect and must never receive lifecycle ownership. Sol alone may build/start/restart/stop/cleanup the shared service.

After `worker-results-merge`, Sol records judged material claims with `record-finding`. Keep the final solver under `exploit/`. Before verification, write `REPRODUCE.json` with schema version 1, direct `argv` (normally using `/artifacts/exploit/...`), current input fingerprint, recommended image/resource profile, service requirement, expected flag pattern, `same_flag_required` (default `false`), optional local/remote success patterns, and a separate `remote_argv` when organizer reproduction needs a different target. Do not put shell pipelines or host commands in the contract.

Call `replay '<selector>' --contest '<name>'`. It validates the fingerprint, runs two independent clean local receipts, keeps the local success marker separate from the remote flag, performs a distinct allowlisted remote replay, verifies actual remote firewall observations, and checks that local and remote use the same exploit path. Different local placeholder and remote real flags are valid by default. Only `FULLY_VERIFIED` may produce `READY_FOR_HUMAN_SUBMISSION`; path mismatch stops at `REMOTE_FLAG_OBTAINED` for Sol judgment. `reproduce.sh` remains a thin wrapper and never runs the exploit on the host.

Return: problem, state, exact verified flag candidate if ready, local/remote/independent/pattern checks, reproduce path, core vulnerability, and the warning that submission is manual. Never claim SOLVED when verification is incomplete.
