# Thin baseline / blind-live promotion bundles

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

Every case inside a split declares one input manifest digest and exactly six
globally unique sessions: attempts 1, 2, and 3 for `thin_scaffold`, and attempts
1, 2, and 3 for `ctf_os`. Each session binds an exact contest/category/challenge
identity. One identity cannot be reused in another arm, case, or repeat.

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
if execution activity already exists. It only writes evaluation binding
metadata through the state store. The engine re-attests this fingerprint when
it records the scaffold launch and again after provider capacity is acquired,
immediately before every model invocation.

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
It re-attests runtime source before and after capture. Activity timestamped
after finalization makes the bundle incomplete.

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
evaluation, rejects reused session IDs/state, and derives:

- solve@1
- pass^2/3
- median time-to-first-valid-result
- proof and clean-reproduction rates
- human interventions
- per-category floor
- public versus blind/live/hidden performance
- same-model, same-budget, and same-execution-fingerprint comparisons

A missing, duplicate, partial, contaminated, leaked, unsafe, or modified
bundle closes promotion. The result can only say
`eligible_for_manual_promotion`; it never changes defaults or submits flags.

## Trust boundary

The local HMAC proves that the same CTF-OS workspace collector created the
frozen manifest and bundles. It does not independently attest provider-side
model execution or observe information leaked outside CTF-OS. Visibility and
manual counters are therefore explicit, pre-bound operator contracts, and the
report exposes these limitations rather than presenting them as externally
verified facts.
