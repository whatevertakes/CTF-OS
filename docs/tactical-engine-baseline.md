# Tactical engine baseline

Recorded before tactical-engine changes on 2026-07-12 (Asia/Seoul).

- Test command: `uv run pytest -q`
- Result: **310 passed in 99.42s**; no failures or skips were reported.
- Sol planning: `CategoryPlanner` renders one strict JSON prompt;
  `SolvePlanParser` validates it; `RacePlan.from_solve_plan` materializes local
  child attempts and `LocalApplication._materialize_solve_plan` persists tasks.
- Tool strategy: one enum-like string was stored on `BranchExecutionSpec` and
  `contract_tasks`. It affected prompt text/profile descriptions and timeout
  lookup, but did not select an image, bootstrap a harness, preflight tools,
  collect strategy-specific artifacts, or choose fallback execution.
- Categories: one canonical top-level category (`pwn`, `web`, `rev`, `crypto`,
  `forensics`, `cloud`, `misc`); there was no durable subtype/variant profile.
- Replanning: `replan_when` and `escalate_when` were required prose strings.
  Runtime supervision reacted to exact `LOOP_DETECTED` or elapsed no-progress,
  then requested a bounded Sol hint; predicates/actions were not executable.
- Loop detector: input was `[ACTION]`/`[FAIL]` text; output was
  `LoopSignal(shift_required, reason, count)` from exact case/space-normalized
  repetition. Inputs, artifacts, crashes, hypotheses and progress were absent.
- Sandbox: one `ctf-os-sandbox:latest` image, one container per attempt,
  manifest-exact endpoint policy, broker-mediated `/work` and `/artifacts`, and
  label-scoped cleanup. `sandbox-tools.txt` described a broad common tool set.
- Artifacts: private attempt staging, parent-approved session handoff, replay
  verifier and final promotion existed; there was no hashed strategy-aware
  provenance table or generic consumer graph.
- Events/DB: SQLite schema version 9; events used durable outbox and attempt
  fencing. Sessions and branch contracts were durable, but profiles,
  capability checks and rule-fire idempotency had no dedicated schema.
- Models: Codex CLI production backend plus a clearly synthetic mock backend;
  routing selected Sol/Terra/Luna profiles with bounded fallbacks.
- Knowledge: deterministic local SQLite/FTS retrieval filtered primarily by
  category and weighted free text; trust/provenance existed, but subtype,
  phase, strategy, platform and primitive were not first-class query fields.
- Benchmarks: unit/integration tests included synthetic vertical slices and
  optional live Docker tests. No versioned, randomized, non-mock real-model
  benchmark suite or A/B report existed.
