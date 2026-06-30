# Level 3 Agent Design Notes

This is the design note and implementation contract for Level 3. The initial
runtime is `tools/level3_orchestrator.py`: a stdlib-only local orchestrator
that creates worker packets, merges worker evidence, maintains attempt and
mutation logs, and evaluates proof readiness through Level 2.

## Inputs From Benchmarks 1-3

The Level 0-2 benchmark recheck produced three durable constraints for future
agent design:

- `pwn_ppp`: remote-solved evidence can contain real flags, so worker output
  must separate raw evidence from redacted reporting.
- `mikuprotect`: local proof can be valid while remote solve fails, so agents
  must model proof scope separately from remote status.
- `DreamFlow`: broad stateful web attempts need negative-probe catalogs and
  worker-specific logs, but the Level 2 evidence contract remains the source of
  truth.

## Required Interface With Level 0-2

Future Level 3 agents should consume these existing contracts instead of
inventing parallel state:

- run `tools/preflight_check.py` before benchmark or solve orchestration
- create challenge workspaces with `tools/intake_challenge.py`
- read the selected `skills/ctf-*/SKILL.md`, `docs/CTF_SOLVE_PLAYBOOKS.md`,
  matching category reference digest, and category reference index before
  probing
- write replay evidence through `tools/replay_runner.py`
- validate claims through `tools/proof_validate.py`
- preserve all machine-readable status in `state.json`
- keep raw and redacted evidence under `evidence/`
- honor `metadata.replay_kind` and never rerun remote live exploits without
  explicit opt-in
- write `metadata.current_remote_liveness` from liveness probes rather than
  inferring it from stale URLs

## Implemented Runtime

`tools/level3_orchestrator.py` provides:

- `init`: run strict preflight and proof validation, then create
  `work/LEVEL3_STATE.json`
- `plan`: create category-specific worker packets in `work/LEVEL3_TASKS.json`
- `packet`: print one worker prompt packet for Codex sub-agent use
- `dispatch`: write `multi_agent_v1.spawn_agent`-ready packet files plus
  `work/LEVEL3_DISPATCH.json` and `work/LEVEL3_DISPATCH.md`
- `assign`: record the actual spawned agent id/status for a dispatched worker
- `merge`: validate worker result JSON, including skill/playbook/digest read
  receipts plus reference query records, and merge it into Level 2 artifacts
- `collect`: merge one result JSON or a directory of worker result JSON files
- `status`: report pending, dispatched, assigned, and merged workers
- `evaluate`: run replay/proof checks and write `metadata.level3_score`
- append-only run log: `work/LEVEL3_RUN_LOG.jsonl`

## Version Contract

- v1: `init`, `plan`, `packet`, `merge`, `evaluate`
- v2: `dispatch`, `assign`, and `collect` for real main-agent-managed
  `multi_agent_v1.spawn_agent` operation
- v3: category and role strategy profiles embedded in every worker packet

The local Python script intentionally does not call `multi_agent_v1.spawn_agent`
directly. It creates spawn-ready packets and a dispatch manifest; the Codex main
agent owns the actual parallel worker calls, then returns JSON files to
`collect`.

`collect` is idempotent for the same worker result path. Re-collecting the same
JSON returns the existing summary without duplicating facts, negatives, or
mutation entries. A different result for an already merged worker is rejected so
the orchestrator does not silently overwrite proof history.

## Category Strategy Profiles

Every task now carries:

- `strategy.playbook`
- `strategy.tools`
- `strategy.evidence_required`
- `strategy.failure_modes`
- `inputs.skill`
- `inputs.solve_playbook`
- `inputs.reference_digest`
- `inputs.reference_index`
- `inputs.reference_query_category`
- `inputs.reference_query_tool`
- `expected_output.reference_queries`
- `expected_output.reference_files_consulted`
- `expected_output.read_receipts`
- `multi_agent.spawn_tool=multi_agent_v1.spawn_agent`

Every major state transition appends a JSONL event to
`work/LEVEL3_RUN_LOG.jsonl`. This keeps the operating loop inspectable without
requiring chat history.

The v3 profiles strengthen the hard categories that produced benchmark misses
and keep all installed CTF skills on the same worker-packet contract:

Category reference digests compress trusted GitHub, CVE/CWE, and paper
guidance into hypothesis prompts without loading full external repositories.
Reference indexes point those digest patterns to pinned local files. Merged
worker results must prove they read the category skill, solve playbook, and
digest, must record evidence-gated reference queries, and must name the exact
local reference files they consulted.

- web: auth/session, source disclosure and XXE, policy oracles, mutation
  ledgers, render/upload behavior, SSRF channels
- pwn: environment reproduction, crash triage, primitive construction,
  exploit chaining, deadline-aware remote runner
- rev: static extraction, concrete tracing, symbolic execution bounded by
  evidence, patch/verify loops
- crypto: parameter extraction, math attack selection, oracle modeling,
  deterministic solver verification
- forensics: inventory, timeline, carving, memory/network chain, crypto bridge
- misc: protocol model, parser state, automation solver, category router
- programming, jail, stego, osint, mobile, malware, web3, cloud, container,
  ai-ml, hardware-rf, side-channel, and hybrid: category-specific worker
  partitions with the same skill/playbook/proof contract

## Organic Connection Rule

Level 3 must not create a parallel truth store. Its worker board should be a
view over Level 2 artifacts:

- facts come from `notes.md`, `state.json`, replay logs, saved responses, and
  challenge-local scripts
- worker tasks write into `work/` and `evidence/`
- global status is merged back into `state.json`
- proof claims still go through `tools/proof_validate.py`
- remote activity is classified through `replay_kind`, `remote_status`,
  `remote_solve`, and `current_remote_liveness`

## Hard-Problem Loop

Level 3 should implement the loop learned from the Level 0-2 benchmarks:

1. Freeze the prompt, endpoints, handouts, and local runtime.
2. Run static and surface analysis before mutating state.
3. Build a hypothesis tree with explicit stop conditions.
4. Assign each branch to a bounded worker.
5. Record both positive evidence and negative probe families.
6. Maintain a mutation ledger for remote state changes.
7. Refresh replay/proof metadata before remote expiry.
8. When blocked, repartition the hypothesis space rather than repeating a
   disproven payload family.

## Non-Goals For Now

- no background scheduler
- no new MCP routing layer
- no Level 3-owned dashboard or report surface; Level 4 reads Level 3 artifacts
  and presents them as an interface view
- no automatic remote exploit reruns

Remote live replay remains guarded by Level 2 metadata and explicit operator
opt-in. Level 3 may schedule or describe a remote attempt, but it must not turn
that into an implicit replay.

## Reference Alignment

The v2-v3 design was checked against harness-engineering references after
implementation:

- Codex subagent guidance: decompose highly parallel tasks, spawn bounded
  workers, and have the main agent consolidate results.
- OpenAI harness engineering: make repo-local instructions, telemetry, and
  validation visible to the agent loop.
- Anthropic long-running harness guidance: keep initializer state, handoff
  artifacts, and self-verification explicit across context windows.
- Loop-engineering references: keep run logs, budgets, state, and failure-mode
  controls in files rather than relying on memory.
- SWE-agent and ReAct research: tool-facing agent loops improve when actions,
  observations, and verification are first-class harness artifacts.
