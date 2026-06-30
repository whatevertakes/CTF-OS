# Level 6 Evaluation Policy

Level 6 measures whether the workspace is improving at CTF solving over time.
It does not solve challenges, mutate challenge state, spawn agents, submit
flags, contact remotes, or clean artifacts. It turns existing Level 1-5 outputs
into evidence-backed readiness and regression signals.

## Role

Level 6 is the evaluation layer above bounded Level 5 automation. Its job is to
answer:

- which benchmark cases exist and which split they belong to
- which categories are covered or missing
- which solved claims are actually proof-valid
- which failures repeat often enough to shape future tooling
- whether a new change regresses replay, proof, reporting, or corpus hygiene
- whether future agent designs are based on repeated evidence instead of names

Level 6 is read-only by default. It may inspect `benchmarks/corpus.yaml`,
challenge `state.json` files, replay evidence metadata, sanitized benchmark
reports, and policy documents. It must not modify those inputs.

## Metrics Tracked

The core inventory metrics are total benchmark corpus entries, counts by
category, counts by split, outcome counts, agent mode counts, missing agent
mode entries, repeated failure taxonomy labels, replay quality summaries,
shareability summaries, and split health warnings.

Integrity metrics are:

- proof validity through `tools/proof_validate.py`
- solved entries missing replay evidence or proof state
- blocked entries missing a blocker reason
- dependency state and missing required tools
- path and state hygiene, including missing challenge paths and stale corpus
  entries whose registry metadata disagrees with existing state
- sanitized benchmark report presence for solved, blocked, and partial entries
- historical solved entries that do not have current proof-valid replay
- tool routing gaps, MCP considered, MCP used, MCP skipped with reasons, and
  MCP absence without a recorded decision

Performance metrics are optional corpus mappings:

- `time_metrics`
- `attempt_metrics`
- `reference_metrics`
- `tool_effectiveness`

Performance metrics are reported as unavailable when solve logs or metadata do
not exist. Missing performance mappings do not fail readiness; they only limit
what Level 6 can compare.

Reports must be aggregate and sanitized. They may reference paths, IDs, status,
split, category, and taxonomy labels. They must not include raw flags, secrets,
raw remote transcripts, or raw exploit output.

## Outcome Definitions

`solved` means the challenge state claims solved and `tools/proof_validate.py`
accepts the claim. A sanitized historical benchmark report may record a previous
solve, but it is not counted as proof-valid unless a current challenge directory
with valid replay evidence exists.

`partial` means there is meaningful progress with evidence or a clear blocker,
but the proof contract for solved is not met.

`blocked` means progress is blocked by a specific reason. A blocked entry
without a blocker reason is an evaluation failure because it cannot guide future
work.

`attempted` means work has started but has not reached solved, partial, or
blocked. Existing Level 1 state values such as `triaged`, `analyzing`, and
`exploiting` normalize to `attempted` for corpus reporting.

`planned` means the corpus entry exists but no meaningful attempt state is
available yet.

## Proof Source Of Truth

`tools/proof_validate.py` is the source of truth for solved claims. Level 6 may
summarize solved counts, but it must not invent a solved verdict. If
`proof_validate.py` rejects an entry, Level 6 reports it as proof-invalid even if
the corpus says `status: solved`.

This keeps false-solved detection centralized:

- solved requires `final_command`
- solved requires replay evidence
- solved requires a non-`none` proof scope
- blocked requires a blocker reason
- sensitive replay logs require redacted summaries

Tool routing metrics are observability caveats, not proof claims. A challenge
may use no MCP tools when CLI tools or local probes produce better evidence.
Skipped MCP tools are acceptable when the reason is explicit, and missing
required tools remain dependency findings.

## Benchmark Splits

`design` entries are used to understand workflow gaps and shape Level 2-5
improvements. Agent design may use design entries as examples, but should not be
trusted only because design entries improve.

`holdout` entries are reserved for checking whether changes generalize. New
write-capable agents should not receive broader permissions until holdout
results improve without increasing false-solved, leakage, or cleanup risk.

`regression` entries are stable checks for previously fixed behaviors. They are
used to prevent replay, proof, cleanup, report, and category coverage regressions.

`agent_mode: none` is the no-agent baseline. Future agent A/B evaluation must
compare each agent mode against that baseline by split and must not grant new
agent capability from benchmark metadata alone.

## Overfitting Prevention

Do not tune agents, prompts, or scripts only to named design fixtures. A change
is not considered broadly useful until it improves at least one holdout or
regression case without weakening proof validation.

Level 6 reports should separate:

- design improvements
- holdout improvements
- regression stability
- historical evidence that cannot currently be replayed

Historical sanitized evidence is useful for architecture lessons, but it does
not replace live proof-valid benchmark evidence.

## Selftest Semantics

`benchmarks/level6_selftest.py` may create intentionally bad fixture corpus
entries under temporary directories. The selftest passes when those expected
failures and warnings are detected correctly and the output stays sanitized. A
passing selftest does not mean the fixture corpus is ready; it means Level 6
recognized the bad fixtures.

## Category Coverage Goals

The corpus should cover at least:

- pwn
- web
- rev
- crypto
- forensics
- misc/programming
- hybrid chains where one category hands off to another

Coverage should include easy, medium, hard, and unknown difficulty cases. A
category is not considered mature just because it has one solved design case.

## Report Safety

Level 6 reports must not include:

- raw flags
- bearer tokens
- private keys
- raw remote transcripts
- raw replay logs containing sensitive markers
- exploit payload bytes when those bytes include challenge secrets

Use sanitized reports such as
`benchmarks/PWN_PPP_SANITIZED_BENCHMARK_REPORT.md` for historical evidence.

## Agent Design Inputs

Level 6 informs future Level 3 agents without overfitting:

- Hermes should be designed from repeated state, blocker, and evidence-gap
  patterns.
- LazyCodex should be designed from repeated notes, replay, report, and cleanup
  hygiene gaps.
- 가재코드 should be designed from repeated bounded-search and search-explosion
  patterns.

Agent write privileges require holdout improvement and no increase in
false-solved, leakage, or destructive cleanup risk.
