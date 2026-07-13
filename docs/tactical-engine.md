# Tactical execution engine

> **Manual-workbench scope:** this engine now supplies subtype classification,
> strategy contracts, capability requirements and Sol prompt context for one
> human-selected Solve Session. It does not own a contest-wide queue, assign
> challenges, retry work, or spawn workers outside `ctf-os solve <challenge>`.

CTF-OS converts Sol's `tool_strategy` into a versioned local execution policy.
The policy selects a capability profile/image, creates an attempt-private
harness, preflights real executables, publishes command templates and expected
artifacts, applies resource budgets, and records fallback/escalation state.
All execution remains inside the existing manifest allowlist, per-attempt
container, `/work`/`/artifacts`, fencing and label-scoped cleanup boundaries.

## Architecture

- `tactical_engine/strategies.py`: declarative `ToolStrategySpec` registry,
  capabilities, harnesses, budgets, progress signals and bootstrap manifests.
- `tactical_engine/profiles.py`: evidence-backed, updateable hierarchical
  `ProblemProfile` classification.
- `tactical_engine/planners.py`: subtype planner registry and concrete tactical
  contracts. Unknown subtypes visibly use `generic.unknown`.
- `tactical_engine/rules.py`: schema-v1 predicates/actions, legacy conversion,
  synchronous evaluation, cooldown/max-fire/idempotency and durable scheduler
  actions.
- `solver_engine/loop_detector.py`: deterministic command/failure
  canonicalization plus semantic progress and plateau scoring.
- SQLite schema v10: `problem_profiles`, `tactical_artifacts` and
  `replan_rule_fires`.

Events retain strategy ID/version, capability outcome and before/after rule
snapshots. Artifact records contain hash, producer/contract, parent, creation
event, strategy, trust state and consumers. Commands and version output are
bounded; credential-like values are redacted and flag contents are not placed
in tactical artifact metadata.

## Adding a strategy

Register a `ToolStrategySpec` with a unique lower-snake-case ID and
`schema_version=1`. Define required/optional executable alternatives, profile,
harness scripts, commands, input/output artifact contracts, progress/failure
signals, resource/network budget, fallback and security restrictions. Add the
profile to `sandbox/profiles.yaml` and, when it needs extra packages, a named
stage in `sandbox/Dockerfile.profiles`. Run:

```bash
uv run python scripts/validate_profiles.py
uv run pytest -q tests/test_tactical_engine.py
```

Unknown future strategy versions are rejected rather than interpreted as v1.

## Adding a subtype planner

Add an evidence rule in `profiles.py`, then register a planner by exact
`(category, subtype)` in `default_planner_registry`. A contract must state a
hypothesis, prerequisites, strategy/harness, commands, artifact inputs/outputs,
success/failure signals, transition conditions, dependencies, cancellation,
timeout and cost. Planner coverage is checked in `test_tactical_engine.py`.
The default registry covers more than 60 named subtypes across pwn, web,
reversing, crypto, forensics, cloud, mobile, password, OSINT, hardware and
misc/protocol. Only genuinely unclassified evidence reaches the visible
generic fallback.

## Structured replan rules

Rules use `schema_version: 1`, unique ID, priority, one recursive `all`/`any`/
`not` predicate, actions, cooldown and max fires. Leaf predicates support
event/field matching and `eq`, `ne`, comparisons, `in`, `contains`, `exists`
and `changed`. Actions cover cancellation, pause/resume intents, planner/contract
spawn, priority, artifact promotion/handoff, model/budget change, escalation,
verification and session termination.

Legacy prose remains readable but becomes a low-priority, 600-second
no-progress escalation rule. Invalid structured rules emit
`rule.validation_failed`; they are never silently ignored. Matching occurs in
the current scheduler tick. The `(rule_id,event_id)` SQLite key prevents
duplicate fire after restart.

## Progress and loop semantics

`ProgressSnapshot` distinguishes command, arguments, input hash, artifact hash,
strategy, hypothesis, failure/crash signature, evidence, artifact/content
change, endpoint/parameter discovery, leak/primitive acquisition,
classification/constraint/coverage/verifier/reliability change and contract
transition. Address, timestamp and path canonicalization plus token-Jaccard
failure clusters work without embeddings or paid APIs. A changed fuzz input or
target artifact is not a loop. A new leak/primitive produces positive progress
and clears plateau pressure.

## Capability profiles

Profiles are `base`, `pwn`, `web`, `browser`, `reversing`, `windows`, `mobile`,
`crypto`, `forensics`, `cloud`, `password`, and `osint`. Deployments may map
them to images through `sandbox.profile_images`; omitted mappings retain the
legacy image for compatibility. Required executable failure marks the harness
degraded and records a fallback. GUI/GPU are optional and never presumed.

```bash
uv run ctf-os capabilities
uv run ctf-os capabilities --json
```

## Migration

`ctf-os state migrate --config config.yaml` upgrades atomically to schema v10.
SQLite `user_version` changes only after the transaction succeeds. Existing
strategy strings and plan prose remain accepted. A DB with a future schema
version is refused. Back up the local contest DB before an operational upgrade.

Use `ctf-os state migrate --dry-run --config config.yaml` to inspect the current
and target versions without creating or modifying the DB.

## Benchmarks

The manifest defines 12 category/subtype fixtures and randomizes every executed
fixture. The quick smoke suite runs three local tool workflows with private
verifier state; it does not claim model calls. Real mode invokes the actual
Codex CLI + Docker runtime when available. Its parent-owned verifier keeps only
a keyed digest in coordinator memory; the reference flag and key are never
mounted, prompted, serialized, or delegated to worker-authored replay code.
Candidate events and reports retain only a SHA-256 digest. A missing backend
never turns into a pass.

```bash
make benchmark-smoke
make benchmark-real       # pwn heap + forensics; authenticated Codex CLI and Docker
make benchmark-compare
make benchmark-compare-real
make smoke-profiles       # build/smoke base, pwn, web, forensics
```

Real fixture selection is repeatable, for example:

```bash
uv run python benchmarks/run.py --mode real --challenge pwn-heap --challenge web-ssrf --seed 4105
```

The executable fixtures include an AF_UNIX format-string service, a one-shot
allocator leak service whose follow-up contract must consume a promoted JSON
artifact, and an HTTP SSRF origin with a separate internal allowlist. Target
containers receive the randomized flag only as a private environment value;
solver containers and workspaces do not.

JSON and Markdown reports are written under `benchmarks/results/` and include
per-challenge status, planner, strategy, failure stage, verifier result,
producer/consumer artifact IDs, replan latency, solved state, metrics and event
timeline. Generated reports are ignored by Git because they contain local run
metadata. Manifest-only fixtures not selected for real mode remain visibly
reported as not run rather than silently skipped.

## Troubleshooting

- `degraded=true`: inspect `strategy-manifest.json` and `ctf-os capabilities`;
  build/map the required profile or allow the recorded fallback.
- No rule fires: inspect `rule.validation_failed`, event type and field path,
  then check cooldown/max-fire and `replan_rule_fires`.
- False loop concern: compare input/artifact hashes and progress delta in the
  `LOOP_DETECTED`/`PLATEAU_DETECTED` payload.
- Profile build issue: run `scripts/validate_profiles.py` before a targeted
  Docker stage build.
