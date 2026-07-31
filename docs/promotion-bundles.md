# Thin baseline / blind-live promotion bundles

> Current authority (2026-08-01): this collector path is implemented and tested,
> but no genuine blind/live thin-scaffold 3×3 versus CTF-OS 3×3 cohort has been
> executed. `COMPETITION_PERFORMANCE_STATUS` therefore remains
> `NOT_ESTABLISHED`. See [RELEASE_STATUS](../RELEASE_STATUS.md); engine release
> acceptance and solve-performance promotion are separate claims.

The old `ctfos benchmark promotion --evidence FILE` command remains a pure,
read-only gate for diagnostics. Operator-written outcome fields are not
engine-derived evidence and must not be used as automatic promotion evidence.

The executable collector path is:

```text
fingerprint -> freeze -> prepare one session -> run it -> finalize -> capture
            -> repeat by explicit operator choice -> compare
```

No command selects, opens, switches, or submits a challenge automatically.

## 1. Pin and inspect the execution environment

Pin the runtime image before freezing a benchmark:

```sh
ctfos pin-image
ctfos benchmark fingerprint
```

`fingerprint` hashes the pinned image ID, the image capability manifest, the
complete configured model-role mapping, and a deterministic inventory of
Git-tracked runtime source. The source inventory includes `ctf_os/**/*.py`,
`pyproject.toml`, and tracked root entrypoints; it excludes mutable challenge
state, incoming artifacts, tests, and documentation. Dirty, symlinked,
oversized, or index-mismatched runtime source fails closed.

Promotion preparation requires every logical model role to name the single
model declared by the manifest.

## 2. Freeze the paired session manifest

The manifest has these top-level fields:

```json
{
  "schema_version": 2,
  "benchmark_id": "promotion-2026-08",
  "model_id": "gpt-5.6-sol",
  "budget": {
    "wall_seconds": 7200,
    "model_call_limit": 64,
    "total_token_limit": 2000000
  },
  "execution_fingerprint": {
    "tool_manifest_sha256": "<fingerprint output>",
    "image_sha256": "<fingerprint output>",
    "model_config_sha256": "<fingerprint output>",
    "engine_source_sha256": "<fingerprint output>"
  },
  "splits": []
}
```

Every case inside a split declares the exact fresh `incoming/` source-manifest
digest and exactly six globally unique sessions: attempts 1, 2, and 3 for
`thin_scaffold`, and attempts 1, 2, and 3 for `ctf_os`. Each session binds an
exact contest/category/challenge identity. One identity cannot be reused in
another arm, case, or repeat.

Required exposure policy:

- `dev`: trajectory visible, answers hidden.
- `regression`: trajectory hidden, answers hidden, prior engine runs positive.
- `blind`, `live`, and optional `hidden`: trajectory and answers hidden, prior
  engine runs zero.

Freeze the complete manifest before any benchmark execution:

```sh
ctfos benchmark freeze \
  --manifest promotion.json \
  --output promotion.frozen.json
```

The frozen document is bound to a private local collector key. Existing output
is never overwritten.

## 3. Prepare, run, finalize, and capture one human-selected session

After the operator creates and inventories the exact challenge state, but
before any model/tool execution:

```sh
ctfos benchmark prepare \
  --manifest promotion.frozen.json \
  --session live-pwn-ctf_os-1
```

Preparation fails if the challenge-source digest, fixed budget,
model/tool/image/engine-source fingerprint, or challenge identity differs, or
if execution activity already exists. It also creates a schema-v1 operator
input commitment over category, description, prompt, the fresh `incoming/`
manifest/files/count/bytes, and the canonical static source inventory. It only
writes evaluation binding metadata through the state store. The engine
re-attests the execution fingerprint, empty knowledge snapshot, and operator
input before and after recording the scaffold launch, and again after provider
capacity is acquired immediately before every model invocation. Prompt,
description, category, incoming bytes, or source inventory changes therefore
fail closed instead of silently changing one arm.

The operator then runs that one session normally. After all activity and manual
outcomes are recorded, finalize the counters that cannot be inferred from an
external provider:

```sh
ctfos benchmark finalize \
  --manifest promotion.frozen.json \
  --session live-pwn-ctf_os-1 \
  --human-interventions 0 \
  --secret-or-flag-leaks 0
```

Capture the now-final session:

```sh
ctfos benchmark capture \
  --manifest promotion.frozen.json \
  --session live-pwn-ctf_os-1 \
  --output bundles/live-pwn-ctf_os-1
```

Capture copies only bounded state-referenced evidence, records every file
digest, evaluates the copied canonical state, and authenticates the bundle.
It emits promotion bundle schema 3 and records the operator-input digest plus
the bounded incoming inventory. Runtime source, knowledge, and operator input
are re-attested during finalization, before and after capture, and again when a
bundle is verified. Activity timestamped after finalization makes the bundle
incomplete.

Preparation also records `evaluation_started_at` exactly once and binds the
canonical bounded `deadline_utc` as
`evaluation_budget_deadline_utc`. Repeating preparation preserves those exact
values. Finalization must follow preparation and remain inside that fixed wall
window; run, artifact, candidate, submission, and proof-completion timestamps
outside the start/finalization interval make collection incomplete.

Promotion wall time is `evaluation_finalized_at - evaluation_started_at`. It
therefore includes provider/model queue and execution wait, while excluding
challenge staging time before explicit preparation. `budget.spent_seconds`
remains operational tool accounting and is not used as the promotion
performance wall. Time-to-first-valid-result uses the same prepared start, not
the canonical state's earlier creation time.

Positive `solved`, `proof_passed`, and `reproduced` fields are candidate-scoped,
not aggregate proof claims. The collector binds every manually accepted
candidate ID and candidate-value SHA-256 from the durable contest submission
ledger to a hash-validated passed proof, its terminal `RunOrigin.PROOF` records,
and its clean reproduction observations. The ledger is checked before and
after capture. The signed bundle retains a sorted redacted snapshot containing
only submission ID, candidate ID, value SHA-256, status, and recorded time.
Verification re-derives candidate bindings from that snapshot rather than the
later live ledger, so an append after capture cannot change historical replay.
Raw candidate values are not copied into the bundle report or derived-attempt
record. All derivation reads the staged, content-addressed capture rather than
the live challenge directory. A proof artifact also cannot claim completion
before any proof run it names was created. One accepted candidate cannot borrow
another candidate's proof, even when the candidate values happen to be equal.
Missing, partial, reordered, or changed links emit an unbound-evidence blocker
and leave all success fields false.

## 4. Compare only after all explicit sessions finish

Pass each bundle explicitly:

```sh
ctfos benchmark compare \
  --manifest promotion.frozen.json \
  --bundle bundles/dev-pwn-thin_scaffold-1 \
  --bundle bundles/dev-pwn-thin_scaffold-2 \
  --bundle bundles/dev-pwn-thin_scaffold-3 \
  --bundle bundles/dev-pwn-ctf_os-1 \
  --bundle bundles/dev-pwn-ctf_os-2 \
  --bundle bundles/dev-pwn-ctf_os-3
```

The complete real manifest will have more bundles. Comparison re-authenticates
the manifest and each bundle, checks the exact file inventory and hashes,
re-attests runtime source before and after verification, re-runs canonical
evaluation, rejects reused session IDs/state, and requires the paired
`thin_scaffold`/`ctf_os` sessions for each case to share one operator-input
digest. It derives:

- solve@1
- pass^2/3
- median time-to-first-valid-result
- proof and clean-reproduction rates
- human interventions
- per-category floor
- wall time, model calls, and total tokens per qualified case and qualified
  attempt, with a total-resource Pareto rule when either denominator is zero
- public versus blind/live/hidden performance
- solve@1, pass^2/3, median time-to-first-valid-result, qualified-result count,
  and human-intervention non-regression for every held-out split/category and
  for each category across all held-out splits
- qualified-resource non-regression for every held-out split/category and for
  each category across all held-out splits
- same-model, same-budget, and same-execution-fingerprint comparisons

A missing, duplicate, partial, contaminated, leaked, unsafe, or modified
bundle closes promotion. The result can only say
`eligible_for_manual_promotion`; it never changes defaults or submits flags.

Wall time, model calls, and total tokens are price-independent resource
measures. They do not attest a provider invoice or monetary spend: the current
bundle schema does not preserve the input/output/cached-token price mix,
service tier, currency, or billed amount. A policy that requires actual billed
cost must therefore keep that condition separately unverified.

The current case schema also binds one immutable challenge input and compares
the `thin_scaffold` and `ctf_os` arms. It does not encode discovery, PoC, and
patch stages or bind before/after source revisions. These bundles cannot by
themselves satisfy a CyberGym-style patch-stage improvement claim; that needs
a later stage/revision schema extension.

The operator-input binding landed in
`d2fb1130b147605ca5d829ff7d20946fb2f3e41f`. Its focused promotion suite passed
74/74 tests in 110.727 seconds. This is implementation evidence, not a completed
blind/live cohort or a solve-performance result. It also does not replace the
pending current-source full suite, clean all-category matrix, or `ctfos doctor`
release checks.

## Trust boundary

The local HMAC proves that the same CTF-OS workspace collector created the
frozen manifest and bundles. It does not independently attest provider-side
model execution or observe information leaked outside CTF-OS. Visibility and
manual counters are therefore explicit, pre-bound operator contracts, and the
report exposes these limitations rather than presenting them as externally
verified facts.
