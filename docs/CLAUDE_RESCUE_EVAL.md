# Claude Rescue Evaluation Contract

This document defines a future controlled SCA replay. It is separate from the frozen CTF-OS solver benchmark A/B/C/D and does not add or modify a benchmark arm, `BENCHMARK_LOCK`, signed schedule, matched block, or evaluator.

No model run is part of this implementation patch. Unit, MCP, hook, integration, and Docker tests establish software behavior only. Solve-performance impact remains **INCONCLUSIVE** until controlled replay data exists.

## Replay treatments

| Arm | Rescue treatment |
|---|---|
| A | Sonnet `standard`, one-shot tools |
| B | Sonnet `standard`, persistent tools |
| C | Sonnet `assisted`, persistent tools |
| D | Opus `deep`, persistent tools |
| E | Fable strategy plus separately operator-started Sonnet/Opus execution |
| F | appropriate execution profile with knowledge lane enabled |

Each matched replay uses the same exact challenge snapshot, typed starting receipts, target revision, authorized network, tool image, host envelope, time limit, objective, blocker, and packet material. Attempts require fresh rescue IDs, isolated sandboxes, and no artifact or model-context reuse. Requested and observed model identity are distinct fields; a missing observation is missing data.

## Measurements

- organizer-oracle remote flag rate
- structurally valid remote-ready handoff rate
- Claude runtime and Codex post-handoff time
- experiments to working PoC and time to first remote interaction
- persistent-session usage and invalid observation rate
- false breakthrough and command repetition rate
- context compaction count
- requested/observed model and profile/subagent/tool counts
- token/tool cost only when runtime evidence actually provides it

A return verdict alone is not success. Remote flags require the protected exact-run receipt and the human submission oracle; remote-ready success requires preregistered, bounded Codex completion criteria.

## Interpretation

SCA replay is for regression and operational comparison. Generalization requires separate held-out or live challenges. Report matched outcomes, uncertainty, routing failures, missing observations, and resource use. Do not infer solve improvement from passing unit tests, Docker smoke, requested model identity, or unverified breakthrough verdicts. Before controlled replay, the only permitted performance conclusion is `INCONCLUSIVE`.
