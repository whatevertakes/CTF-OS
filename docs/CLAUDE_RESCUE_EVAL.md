# Claude Rescue Evaluation Contract

This document defines a future controlled SCA replay. It is separate from the frozen CTF-OS solver benchmark A/B/C/D and does not add a Claude arm to `BENCHMARK_LOCK`, its signed schedule, matched blocks, or evaluator.

No model run is part of the implementation patch. Unit and integration tests establish policy and software behavior only. Solve-performance impact remains **INCONCLUSIVE** until controlled replay data exists.

## Proposed replay treatments

| Arm | Rescue treatment |
|---|---|
| A | `standard`: Sonnet single solver |
| B | assisted evidence: Sonnet main plus bounded Haiku evidence/recon |
| C | assisted full: Sonnet main plus Haiku and one Sonnet builder/alternate lane |
| D | `deep`: Fable requested main plus bounded Haiku/Sonnet agents |

Each matched replay must use the same exact challenge snapshot, starting typed receipts, target revision, authorized network, tool image, host envelope, time limit, objective, blocker, and packet material. Attempts require fresh rescue IDs, isolated sandboxes, and no artifact or model-context reuse. Requested and observed model identity are distinct fields; missing observed identity is missing data, not requested identity.

## Measurements

- organizer-oracle remote flag rate
- structurally valid remote-ready handoff rate
- Claude runtime to return
- Codex time from validated handoff to protected remote flag receipt
- command-family repetition and repetitions without new evidence
- `NO_NEW_PATH` rate
- false breakthrough rate
- requested versus observed lead model and fallback observations
- profile-level command, runtime, and resource use

Secondary diagnostics may include experiments to PoC, first remote interaction, invalid return rate, target mismatch, and Codex refutation rate. A return verdict alone is not success; remote flags require the existing verified receipt and human oracle, while remote-ready success requires bounded Codex completion criteria preregistered before replay.

## Reporting

Report matched outcomes, uncertainty, environment/model-routing failures, missing observations, and per-profile usage. Do not claim improvement from test passage, a small anecdotal sample, requested Fable routing, or unverified breakthrough verdicts. Before a controlled replay is complete, the only permitted performance conclusion is `INCONCLUSIVE`.
