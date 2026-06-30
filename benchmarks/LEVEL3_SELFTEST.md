# Level 3 Self-Test Benchmark

The Level 3 self-test verifies the orchestration layer on blind synthetic
fixtures across common hard CTF categories. It does not solve real benchmark
services; it checks that hard-problem coordination artifacts are created,
merged, replayed, and validated.

Run from the workspace root:

```bash
python3 benchmarks/level3_selftest.py
```

Expected result:

- strict Level 0 preflight passes
- fixtures are created for every standard CTF category supported by the local
  skill set: `web`, `pwn`, `rev`, `crypto`, `forensics`, `misc`,
  `programming`, `jail`, `stego`, `osint`, `mobile`, `malware`, `web3`,
  `cloud`, `container`, `ai-ml`, `hardware-rf`, `side-channel`, and `hybrid`
- `tools/level3_orchestrator.py init` creates `work/LEVEL3_STATE.json`
- `plan` creates category-specific worker packets in `work/LEVEL3_TASKS.json`
- each task has v3 `strategy` fields and a `multi_agent_v1.spawn_agent`
  contract
- each task includes category `inputs.skill`,
  `inputs.solve_playbook=docs/CTF_SOLVE_PLAYBOOKS.md`, and
  `inputs.reference_digest`, `inputs.reference_index`,
  `inputs.reference_query_category`, and `inputs.reference_query_tool`
- `packet` emits a self-contained worker prompt packet that requires
  skill/playbook/digest read receipts plus evidence-gated reference queries
- `dispatch` writes `work/LEVEL3_DISPATCH.json`,
  `work/LEVEL3_DISPATCH.md`, and worker packet files
- `assign` records the spawned-agent id/status for the selected worker
- `collect` validates worker result JSON from `work/level3_results/`,
  rejects missing read receipts or reference query records, writes worker evidence, updates
  `ATTEMPT_MATRIX.md`, `MUTATION_LEDGER.md`, `notes.md`, and `state.json`
- `work/LEVEL3_RUN_LOG.jsonl` records `init`, `plan`, `dispatch`, `assign`,
  `collect`, and `evaluate`
- `evaluate --run-replay` runs safe local replay, proof validation, and records
  `metadata.level3_score`

To inspect generated fixtures:

```bash
python3 benchmarks/level3_selftest.py --keep
```
