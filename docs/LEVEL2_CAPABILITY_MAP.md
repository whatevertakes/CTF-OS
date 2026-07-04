# Level 2 Capability Map

Level 2 is a small local capability layer for CTF work in this workspace. It favors evidence, reproducible commands, and narrow local helpers over broad tool installs or copied external collections.

## Capability Groups

| Group | Purpose | Local entry points |
|---|---|---|
| Preflight | Verify Level 0/1/2 prerequisites before replay or benchmark work. | `tools/preflight_check.py` |
| Intake and state | Create a challenge workspace with a consistent notes, state, replay, and evidence layout. | `tools/intake_challenge.py`, `templates/challenge/` |
| Replay and proof | Re-run exact local commands, write raw evidence plus redacted summaries, and validate whether a claimed solve is backed by evidence. | `tools/replay_runner.py`, `tools/proof_validate.py` |
| Category skills | Give future agents compact routing contracts and category workflows for each CTF category. | `skills/ctf-*/SKILL.md`, generated `.agents/skills/ctf-*` symlinks |
| Solve playbooks | Provide practical first-pass, branch, and stop-condition guidance for real solves. | `docs/CTF_SOLVE_PLAYBOOKS.md` |
| Web helpers | Provide narrow local wrappers for common web CTF workflows without polluting root `tools/`. | `.codex/bin/tplmap`, `.codex/bin/searchsploit` |
| Hybrid chains | Describe cross-category workflows where the solve path crosses boundaries. | `skills/ctf-hybrid-chain/SKILL.md`, `docs/LEVEL2_HYBRID_CHAINS.md` |
| Curated references | Track reputable GitHub, official CVE/CWE, category deep-dive material, pinned local cache, and evidence-gated lookup without default loading. | `references.yaml`, `references.lock.json`, `docs/reference-digests/`, `docs/reference-index/`, `.cache/references/`, `tools/reference_query.py`, `docs/CATEGORY_REFERENCE_MAP.md` |
| MCP bridges | Record configured local or plugin MCP capabilities without loading them by default. | `.codex/bin/*`, `mcp://*` entries in `capabilities/registry.yaml` |
| Interface views | Present Level 1 config, Level 2 state/evidence, and Level 3 worker boards through challenge-local CLI/editor/terminal/browser/report surfaces. | `tools/level4_interface.py`, `docs/LEVEL4_INTERFACES.md` |
| Bounded automation | Wrap existing Level 2 preflight, replay, proof, sanitization, cleanup, and dummy benchmark workflows without adding solve capability. | `tools/benchmark_runner.py`, `tools/report_sanitize.py`, `tools/cleanup_artifacts.py`, `docs/LEVEL5_AUTOMATION_POLICY.md` |
| External references | Track useful public resources as references only, with import and licensing notes. | `docs/LEVEL2_IMPORT_POLICY.md` |
| Benchmarks | Keep a lightweight self-test that proves the layer can create, replay, and validate a challenge. | `benchmarks/level2_selftest.py`, `benchmarks/LEVEL2_SELFTEST.md` |

## Common Registry Schema

Every capability entry in `capabilities/registry.yaml` has these fields:

| Field | Meaning |
|---|---|
| `id` | Stable machine-readable capability id. |
| `type` | One of `script`, `template`, `skill`, `benchmark`, `document`, `external`, or `mcp`. |
| `category` | Primary CTF or workspace category. |
| `status` | Current availability status. |
| `path` | Local path, URL, or MCP identifier. |
| `dependencies` | Explicit dependencies needed before use. Use an empty list for none. |
| `loads_by_default` | Whether future agents should load it during generic CTF startup. |
| `future_agents` | Agent roles expected to consume the capability. |

## Skill Contract Schema

Each `SKILL.md` in this layer is also exposed as a repo-scoped Codex skill
through generated `.agents/skills/<name>` symlinks. The source of truth remains
`skills/<name>/SKILL.md`; `tools/bootstrap_wsl2.sh` regenerates the symlinks
during team setup, and they are intentionally not tracked in Git.

Each `SKILL.md` in this layer uses the same concise contract fields:

- `purpose`
- `when_to_use`
- `when_not_to_use`
- `inputs`
- `outputs`
- `dependencies`
- `evidence produced`
- `failure/blocker classes`
- `future agent consumers`
- `pointers`
- `reference_digest`

The skeletons are intentionally short. They are routing contracts, not encyclopedias.

## Status Model

| Status | Meaning |
|---|---|
| `implemented` | Local file exists and is ready for use. |
| `external` | Public reference or optional tool. It is not vendored and does not load by default. |
| `mcp` | Configured MCP integration or wrapper. Load only when a challenge needs it. |
| `gap` | Known future need. Use only in docs, not for current registry entries unless a concrete placeholder is required. |

## Future-Agent Consumers

Future agents should use this layer in this order:

1. Start with intake for a new challenge.
2. Fix the prompt, remote endpoints, provided files, and local runtime before exploit work.
3. Pick exactly one category skill and read `docs/CTF_SOLVE_PLAYBOOKS.md` for the practical solve loop.
4. Add hybrid-chain guidance only if evidence crosses categories.
5. Read the category reference digest and index, then query local references only after local files and reproducible commands show a need.
6. Keep replay logs and proof validation results under the challenge `evidence/` directory.
7. Keep replay summaries next to raw logs as `evidence/replay_<timestamp>.summary.md`.
8. Update `state.json` when status, proof scope, remote status, replay kind,
   current remote liveness, final command, blockers, evidence paths, replay
   quality, shareability, agent mode, failure class, or tool effectiveness
   changes.
9. Use Level 4 interface views for operator speed, but keep solve status and proof scope in Level 2 state.
10. Use Level 5 automation only for bounded preflight/replay/proof/report/cleanup wrappers.
11. When progress stalls, split the hypothesis space instead of repeating disproven payload families.

## State Metadata Contract

`state.json.metadata` must carry these machine-readable fields:

| Field | Purpose |
|---|---|
| `proof_scope` | `none`, `local`, `remote`, or a short precise scope such as `local verifier proof for round 01/10`. |
| `remote_status` | Current remote result, such as `not_attempted`, `solved`, `failed_no_flag`, `expired`, or a challenge-specific failure string. |
| `remote_solve` | Coarse solve state: `not_attempted`, `attempted`, `failed`, or `solved`. |
| `replay_kind` | One of `local`, `local_proof`, `remote_liveness`, `remote_live`, `remote_live_exploit`, or `remote_saved_evidence`. |
| `current_remote_liveness` | One of `not_applicable`, `unknown`, `live`, `partial`, `expired`, or `unavailable`. |
| `evidence_sensitivity` | One of `no_sensitive_markers`, `contains_flag`, `contains_secret`, or `unknown`. |
| `last_replay` | Object describing the most recent replay timestamp, sensitivity, replay kind, liveness, and artifacts. |
| `agent_mode` | One of `none`, `assisted`, `autonomous`, `hermes_readonly`, `lazycodex_readonly`, or `gajae_bounded`; ordinary Codex solves use `assisted`. |
| `failure_class` | `none` for solved challenges; for blocked or partial challenges use the narrowest label supported by `docs/FAILURE_TAXONOMY.md`. |
| `replay_quality` | Short description of local/remote proof quality, determinism, redaction, summary-only status, and proof validation result. |
| `shareability` | Short description of what can be committed or shared and what must stay local. |
| `tool_effectiveness` | Object mapping important tools to concise labels such as `high`, `medium`, `low`, `skipped_low_value`, `missing_dependency`, or `not_applicable`. |

`tools/proof_validate.py` enforces the proof-critical subset.
`tools/validate_data_submission.py` enforces the full benchmark data contract,
including agent-design metadata and the structured blocker object.
`tools/replay_runner.py` updates `current_remote_liveness` when replay output
contains a `remote_liveness=...` marker.

## Replay Safety

`tools/replay_runner.py` refuses to run `replay_kind=remote_live` or
`replay_kind=remote_live_exploit` unless `--allow-remote-live` is supplied.
Use this for saved remote exploits that may print real flags, mutate live
state, or decay after the CTF service closes. For old evidence, use:

```bash
python3 tools/replay_runner.py --summarize-existing <challenge-dir>
```

## Benchmark-Driven Rules

The first three self-test benchmarks established these Level 2 requirements:

- Remote solved proof must be distinguishable from local-only proof.
- Failed remote attempts must stay valid evidence, not overwrite local proof.
- Replay logs with flag-like markers require redacted summaries before proof validation passes.
- `partial` status requires either durable evidence entries or a blocker reason.
- `state.json` evidence entries must be relative paths that exist inside the challenge directory.
- `solved` status requires a non-empty `final_command`, replay evidence, and a non-`none` `proof_scope`.
- `solved` status requires `metadata.failure_class` set to `none` for data submission.
- Terminal data submissions require non-empty replay quality, shareability, and tool effectiveness metadata.
- Remote live exploit replay requires explicit opt-in.
- Level 3 worker results must include read receipts for the category skill, solve playbook, and reference digest before merge.
- Level 3 worker results must include reference query records and consulted local reference files before merge.
