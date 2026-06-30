# Level 6 Agent Design Inputs

Level 6 does not add agents. It records the evidence required before Level 3
agents should gain new responsibility.

## Hermes Inputs

Hermes should be designed only after repeated evaluation results show state,
blocker, or evidence gaps. Relevant Level 6 signals include:

- blocked entries missing blocker reasons
- partial entries with unclear next action
- stale corpus status versus challenge state
- proof-invalid solved claims
- repeated `evidence_gap` or `state_drift` taxonomy labels

Initial Hermes behavior should be read-only: summarize state, classify blockers,
rank next actions, and point to evidence gaps. It should not edit `state.json` or
declare solved.

## LazyCodex Inputs

LazyCodex should be designed from repeated hygiene failures rather than from a
generic cleanup role. Relevant Level 6 signals include:

- missing sanitized reports
- replay summaries not present for sensitive evidence
- stale corpus entries
- notes or evidence paths that do not match proof validation
- repeated `replay_gap`, `report_hygiene`, or `shareability_gap` taxonomy labels

Initial LazyCodex behavior should be read-only or report-only: index evidence,
summarize hygiene gaps, and produce commit-safe reporting. It should not delete
files or rewrite challenge state.

## 가재코드 Inputs

가재코드 should be designed only when repeated benchmarks show bounded search is
the bottleneck. Relevant Level 6 signals include:

- repeated `search_explosion`
- repeated `repeated_negative`
- repeated `mutation-heavy`
- high retry counts with bounded local-only experiments
- timeouts in local mutation or parameter search

Initial behavior should produce bounded search plans and candidate sets. It
should not run remote loops, mutate state, or claim solved.

## Permission Gates

Read-only agents may be prototyped from design split evidence. Write-capable
agents require:

- measurable improvement on holdout entries
- no increase in proof-invalid solved claims
- no increase in raw flag or secret leakage
- no destructive cleanup incidents
- regression split stability

Autonomous agents require stronger evidence than write-capable agents. A design
entry improvement alone is not enough.

## Anti-Overfitting Rules

Do not grant permissions because an agent improves one named benchmark. Compare
design, holdout, and regression splits separately. If a change improves design
cases but degrades holdout or regression cases, it is not ready.

Do not design or authorize an agent from one benchmark result. Treat one result
as a prompt for more measurement, not as permission to expand capability.
