# CTF Solver Memory

This file is the durable local memory for lessons learned from Level 0-2. It
exists so future agents do not rely on chat history.

## Level 0 Lessons

- Keep the active workspace rooted at `/home/choijiwng/02_ctf_workspace`.
- Prefer Ubuntu WSL2 plus narrow tooling over a full Kali migration.
- Docker is required for strict Level 0 closure because many pwn and web
  challenges depend on the provided jail or service topology.
- Strict preflight must verify both command presence and Docker daemon
  reachability.
- Existing local tools are part of the profile: `checksec`, `ROPgadget`,
  `one_gadget`, `ropper`, `seccomp-tools`, `jadx`, `apktool`, `sage`, and
  `tshark`.

## Level 1 Lessons

- Reasoning and sandbox settings are part of the benchmark contract:
  `xhigh`, `danger-full-access`, and `approval_policy=never`.
- MCPs are optional accelerators, not the source of truth. Evidence still lives
  in challenge directories.
- Reverse-engineering MCPs should route through `.codex/bin/` wrappers when a
  wrapper exists.

## Level 2 Lessons

- A solve claim is not valid until `proof_validate.py` accepts the challenge.
- Raw replay logs can contain real flags. Always generate redacted summaries.
- `remote_status`, `remote_solve`, `proof_scope`, `replay_kind`,
  `current_remote_liveness`, and `evidence_sensitivity` must stay separate.
- Failed remote attempts are evidence. They must not overwrite valid local
  proof.
- `remote_live` and `remote_live_exploit` replays require explicit opt-in.

## Benchmark Lessons

- `pwn_ppp` is the positive remote-solve control. It proves sensitive replay
  handling and remote proof scope.
- `mikuprotect` is the local-proof/remote-failure control. It needs deadline
  modeling, online transcript capture, and faster per-round strategy selection.
- `DreamFlow` is the multi-branch web failure control. It needs role-specific
  workers, mutation ledgers, negative-probe catalogs, and remote liveness
  tracking.

## Hard-Problem Rule

When a difficult challenge stalls, do not keep trying random payloads. Freeze
the environment, split the hypothesis space, assign bounded branches, record
negative evidence, and merge only reproducible facts back into `state.json` and
`notes.md`.

## Level 3 Runtime Memory

- Use `tools/level3_orchestrator.py` for hard-problem orchestration.
- Generate worker packets with `packet`; use `dispatch` when parallel
  `multi_agent_v1.spawn_agent` work is useful.
- The main Codex agent reads `work/LEVEL3_DISPATCH.json`, spawns bounded
  workers, records spawned ids with `assign`, and merges returned JSON files
  with `collect`.
- Merge only JSON worker results that point to existing challenge-local
  evidence.
- Every Level 3 transition should leave durable state in
  `work/LEVEL3_RUN_LOG.jsonl`; chat history is not the source of truth.
- Blind benchmark coverage must span every standard installed CTF category;
  DreamFlow and mikuprotect are regression signals, not the whole target set.

## Level 3 v2-v3 Lessons

- Subagents are useful only when their work partitions the hypothesis space.
  Spawn role-specific workers for independent branches, not for repeated
  versions of the same probe.
- Keep orchestrator, worker, and verifier responsibilities separate:
  workers gather facts and negatives; the orchestrator merges; Level 2 replay
  and proof validation decide durability.
- Strategy profiles must travel inside each packet so a fresh worker can start
  without relying on parent chat context.
- Worker packets must point to both the category skill and
  `docs/CTF_SOLVE_PLAYBOOKS.md`; otherwise downloaded skills become passive
  inventory instead of active solve guidance.
- Worker packets must also point to the category reference digest, and merge
  must reject results that lack read receipts for skill, playbook, digest,
  applied rules, and evidence contract.
- Curated GitHub, CVE/CWE, and paper references are stored as manifest and
  digest data. They guide hypotheses; they are not proof.
- Pinned reference repos live under `.cache/references/`; category indexes
  under `docs/reference-index/` and `tools/reference_query.py` provide
  evidence-gated lookup. Worker results should record both queries and exact
  files consulted.
- Deadline-sensitive pwn work needs timing tables, retry budgets, and
  transcript capture. It must not bypass the remote-live replay guard.
- Rev symbolic work should start from concrete static/dynamic evidence and
  verify candidates on original semantics.
- Web multi-branch work should separate auth/session, source and XXE, policy
  oracle, state mutation, render/upload, and SSRF branches.
- Crypto work should keep parameter extraction, oracle modeling, attack script,
  and independent verifier as separate artifacts.
- Forensics work should preserve artifact hashes, offsets, extraction commands,
  timeline joins, and memory/network provenance.
- Run logs, budgets, and failure-mode records matter because hard CTF solves
  fail by state rot and repeated negatives as often as by missing tools.

## Level 4 Interface Memory

- Level 4 is a view layer over Level 1 config, Level 2 state/evidence, and
  Level 3 orchestration artifacts. It must not become a separate solve engine.
- Use `tools/level4_interface.py build <challenge-dir>` to create
  `work/LEVEL4_INTERFACE.json` and `work/LEVEL4_STATUS.md`.
- Level 4 metadata in `state.json` is limited to pointers:
  `level4_status`, `level4_version`, `level4_manifest`, and `level4_report`.
- Browser or Playwright work is an interface surface, not default probing.
  Only use it after a concrete local or owned target is identified, and save
  screenshots or traces under `evidence/`.
- The useful operator loop is now organic: Level 1 config controls available
  surfaces, Level 2 controls proof and replay truth, Level 3 controls worker
  boards, and Level 4 makes those surfaces fast to inspect from CLI/editor/
  terminal/browser/report views.

## Level 5 Automation Memory

- Level 5 is bounded automation over existing Level 2 workflows only:
  preflight, dummy benchmark wrapping, replay/proof orchestration, sanitized
  reporting, and temporary artifact cleanup.
- Level 5 must never mark a challenge solved. `tools/proof_validate.py` remains
  the solved-claim validator.
- Level 5 benchmark inputs must not live under `challenges/_selftest`; use
  controlled temporary fixtures such as `challenges/_level5benchmark/...`.
- Cleanup automation is dry-run by default and must refuse real challenge paths
  and tracked git files.
- Sanitized reports may be committed; raw replay logs containing flags,
  binaries, dumps, secrets, and `_selftest` artifacts must not be committed.

## Reference-Backed Harness Memory

- OpenAI harness guidance supports making repository-local knowledge, tools,
  logs, metrics, and feedback loops legible to Codex rather than relying on
  prompt memory alone.
- OpenAI Codex subagent guidance supports explicit spawning for parallel,
  highly decomposable tasks, with the parent workflow collecting consolidated
  results.
- Anthropic long-running harness guidance supports initializer/planner state,
  incremental workers, structured handoff artifacts, and self-verification
  before marking work complete.
- Loop-engineering guidance supports explicit budgets, append-only run logs,
  pause/kill criteria, and separate verifier behavior for unattended loops.
- SWE-agent and ReAct support the same direction at the research level:
  agent-computer interfaces and interleaved act/observe loops improve
  difficult task performance when evidence and tools are built into the
  harness.

Reference URLs checked for this memory:

- https://openai.com/index/harness-engineering/
- https://developers.openai.com/codex/subagents
- https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents
- https://www.anthropic.com/engineering/harness-design-long-running-apps
- https://www.anthropic.com/engineering/multi-agent-research-system
- https://arxiv.org/abs/2405.15793
- https://github.com/code-yeongyu/lazycodex
- https://github.com/cobusgreyling/loop-engineering
- https://github.com/Yeachan-Heo/gajae-code
- https://github.com/walkinglabs/awesome-harness-engineering
