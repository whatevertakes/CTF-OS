# Level 2 To Level 3 Handoff

Level 0-2 is now the evidence and proof substrate. Level 3 should build solve
orchestration on top of it rather than replacing it.

## Closure Criteria Before Level 3

- `python3 tools/preflight_check.py --strict-optional` passes.
- `python3 benchmarks/level2_selftest.py` passes.
- `python3 benchmarks/level3_selftest.py` passes after Level 3 changes.
- Existing benchmark states pass `tools/proof_validate.py`.
- Remote live exploit replay is guarded by `metadata.replay_kind`.
- New challenge templates include the strict metadata contract.

## Level 3 Inputs

Level 3 receives:

- challenge root path
- category skill path
- current `state.json`
- current `notes.md`
- replay/proof status
- optional benchmark memory from `docs/CTF_SOLVER_MEMORY.md`
- practical solve guidance from `docs/CTF_SOLVE_PLAYBOOKS.md`

## Level 3 Outputs

Level 3 must write:

- `work/LEVEL3_STATE.json`
- `work/LEVEL3_TASKS.json`
- worker notes under `work/`
- multi-agent dispatch manifest under `work/LEVEL3_DISPATCH.json`
- dispatch operator view under `work/LEVEL3_DISPATCH.md`
- append-only run log under `work/LEVEL3_RUN_LOG.jsonl`
- positive and negative evidence under `evidence/`
- mutation ledger under `work/MUTATION_LEDGER.md` when remote state changes
- attempt matrix under `work/ATTEMPT_MATRIX.md` for broad search trees
- updated `state.json`
- updated `notes.md`
- replay summary and proof validation result before claiming solved

## Worker Roles

Use workers only when the search tree is broad enough to justify them:

- orchestrator: global hypotheses, stop conditions, merge decisions
- hypothesis: hypothesis tree, branch repartition, negative deduplication
- auth/session: identity, cookies, claims, role transitions
- source/disclosure: source reads, file reads, parser behavior
- policy/oracle: ACL, grants, SQL or expression oracles
- state mutation: API method scans, object ownership, side effects
- render/runtime: preview, upload, archive, scheduler, template behavior
- SSRF/internal: internal services, URL parser differentials, side effects
- pwn deadline: timing, retry budget, local/remote delta, transcript capture
- rev symbolic/patch: bounded constraints, patch diffs, unpatched verification
- crypto oracle/model: oracle contract, transcript, local model, solver check
- forensics chain: artifact inventory, timeline, carving, memory/network joins
- evidence: replay, proof, redaction, liveness, report hygiene

## CLI Contract

Use these entrypoints:

```bash
python3 tools/level3_orchestrator.py init <challenge-dir>
python3 tools/level3_orchestrator.py plan <challenge-dir>
python3 tools/level3_orchestrator.py packet <challenge-dir> --worker <role>
python3 tools/level3_orchestrator.py dispatch <challenge-dir> --workers <role1,role2> --limit 2
python3 tools/level3_orchestrator.py assign <challenge-dir> --worker <role> --agent-id <spawned-agent-id>
python3 tools/level3_orchestrator.py collect <challenge-dir> work/level3_results
python3 tools/level3_orchestrator.py merge <challenge-dir> work/<result>.json
python3 tools/level3_orchestrator.py evaluate <challenge-dir> --run-replay
```

For real v2 operation, the main Codex agent reads `work/LEVEL3_DISPATCH.json`,
spawns one sub-agent per selected packet with `multi_agent_v1.spawn_agent`, then
places returned worker JSON files under `work/level3_results/` and runs
`collect`. `merge` remains available for one-off result files.

Worker result JSON must include `worker`, `status`, `facts`,
`negative_results`, `mutations`, `artifacts`, `next_hypotheses`, and
`stop_reason`.

Each task packet also includes v3 strategy fields: `strategy.playbook`,
`strategy.tools`, `strategy.evidence_required`, `strategy.failure_modes`, and
the `multi_agent.spawn_tool` contract. It must also include both
`inputs.skill` and `inputs.solve_playbook` so workers read the category skill
and practical solve loop before probing.

## Merge Rule

Workers do not directly declare solved. They submit facts with evidence paths.
The orchestrator updates `state.json`, then `replay_runner.py` and
`proof_validate.py` decide whether the final claim is durable.
