# Failure Taxonomy

Level 6 uses these labels to classify why a CTF attempt did not reach a
proof-valid solve. Labels are descriptive evidence, not blame, and do not imply
that an agent should be added.

| Label | Meaning | Typical Evidence |
| --- | --- | --- |
| `env_missing` | Required local runtime, service, file, container, or emulator is missing. | Preflight or setup error, missing binary, missing service dependency. |
| `dependency_missing` | A specific library, package, plugin, or optional tool is missing. | Import failure, tool not found, unavailable solver dependency. |
| `wrong_hypothesis` | The current theory of the challenge is contradicted by evidence. | Negative probe, failed decryption model, wrong bug class. |
| `primitive_gap` | The broad direction is right but a necessary primitive is absent. | No leak, no write primitive, no oracle, missing gadget. |
| `leak_missing` | Exploitation or recovery needs a leak that has not been obtained. | ASLR/PIE unknown, key material missing, hidden state not recovered. |
| `exploit_unstable` | The solve path works intermittently or only under narrow timing/state. | Flaky local replay, crash variance, partial remote success. |
| `remote_env_mismatch` | Local proof differs from remote behavior. | Local solve with remote failure, service version mismatch. |
| `search_explosion` | Candidate space is too large without better pruning or batching. | Many payloads, keys, paths, or states with no bounded plan. |
| `replay_gap` | The final action cannot be repeated through the replay contract. | Missing `replay.sh`, non-executable replay, replay not deterministic. |
| `evidence_gap` | The state claim lacks supporting files, paths, or summaries. | Missing replay log, missing proof scope, unsanitized raw report. |
| `false_success_risk` | The current result could be mistaken for solved without proof. | Status says solved but proof validation fails. |
| `timeout` | Work stopped due to time budget rather than a technical conclusion. | Timebox exhausted, long-running search, stuck remote wait. |
| `unknown` | Failure is not yet classified. | Insufficient evidence. |

Use the narrowest label supported by evidence. `unknown` is acceptable when the
state is genuinely unclear, but repeated `unknown` results should drive better
notes and blocker capture.
