# Level 2 Capability Map

Level 2 is a small local capability layer for CTF work in this workspace. It favors evidence, reproducible commands, and narrow local helpers over broad tool installs or copied external collections.

## Capability Groups

| Group | Purpose | Local entry points |
|---|---|---|
| Intake and state | Create a challenge workspace with a consistent notes, state, replay, and evidence layout. | `tools/intake_challenge.py`, `templates/challenge/` |
| Replay and proof | Re-run exact local commands and validate whether a claimed solve is backed by evidence. | `tools/replay_runner.py`, `tools/proof_validate.py` |
| Category skills | Give future agents compact routing contracts for each CTF category. | `skills/ctf-*/SKILL.md` |
| Hybrid chains | Describe cross-category workflows where the solve path crosses boundaries. | `skills/ctf-hybrid-chain/SKILL.md`, `docs/LEVEL2_HYBRID_CHAINS.md` |
| MCP bridges | Record configured local or plugin MCP capabilities without loading them by default. | `.codex/bin/*`, `mcp://*` entries in `capabilities/registry.yaml` |
| External references | Track useful public resources as references only, with import and licensing notes. | `docs/LEVEL2_IMPORT_POLICY.md` |
| Benchmarks | Keep a lightweight self-test that proves the layer can create, replay, and validate a challenge. | `benchmarks/level2_selftest.py`, `benchmarks/LEVEL2_SELFTEST.md` |

## Common Registry Schema

Every capability entry in `capabilities/registry.yaml` has these fields:

| Field | Meaning |
|---|---|
| `id` | Stable machine-readable capability id. |
| `type` | One of `script`, `template`, `skill`, `benchmark`, `external`, or `mcp`. |
| `category` | Primary CTF or workspace category. |
| `status` | Current availability status. |
| `path` | Local path, URL, or MCP identifier. |
| `dependencies` | Explicit dependencies needed before use. Use an empty list for none. |
| `loads_by_default` | Whether future agents should load it during generic CTF startup. |
| `future_agents` | Agent roles expected to consume the capability. |

## Skill Contract Schema

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
2. Pick exactly one category skill, then add hybrid-chain guidance only if evidence crosses categories.
3. Use MCPs and external references only after local files and reproducible commands show a need.
4. Keep replay logs and proof validation results under the challenge `evidence/` directory.
5. Update `state.json` when status, final command, or blockers change.
