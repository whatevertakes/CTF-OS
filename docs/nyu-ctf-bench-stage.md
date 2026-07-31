# NYU CTF Bench operator staging

`ctfos benchmark nyu-stage` prepares an explicitly selected, fixed NYU CTF
Bench cohort. It reads an operator-pinned local checkout only. It does not
clone, download, choose a case, start a service or model, add a network target,
emit a writeup/reference/solver/flag field, or submit a flag.

The bounded verifier necessarily parses each local `challenge.json`, whose
source object may contain hidden material. It immediately projects only the
allowlisted public `category`, `name`, `description`, and `files` values; no
hidden field is emitted to `incoming/`, model-visible state, the manifest, or
the command result. The result therefore attests
`model_visible_external_writeup_or_flag_access: false`, not that the local
source verifier never held hidden metadata in memory.

The source checkout must be a real directory with a clean Git worktree, and
`HEAD` must exactly equal the full `--release-commit`. Clean status alone is
not accepted as a content binding: every consumed dataset, challenge metadata,
and declared asset must also match the corresponding blob in that commit.
This catches locally substituted tracked content even when Git's
`skip-worktree` or `assume-unchanged` flags suppress ordinary status output;
an ignored or otherwise untracked consumed input is rejected. Repository-local
Git filter/include configuration is also rejected before the cleanliness check
so source verification cannot invoke a checkout-defined clean filter. Before staging,
pin the CTF-OS runtime image and keep every logical role on one model so the
current promotion execution fingerprint can be recorded.

Specify every case ID yourself. At least one case from each of `pwn`, `web`,
`rev`, `crypto`, `forensics`, and `misc` is required:

```sh
ctfos benchmark nyu-stage \
  --source /srv/bench/NYU_CTF_Bench \
  --release-commit FULL_RELEASE_COMMIT \
  --case 2021f-pwn-horrorscope \
  --case 2021q-web-no_pass_needed \
  --case 2021f-rev-maze \
  --case 2021f-cry-interoperable \
  --case 2021f-for-no_time_to_register \
  --case 2021f-msc-terminal_velocity \
  --contest nyu-v20250206-dev \
  --split dev \
  --budget-wall-seconds 7200 \
  --budget-model-calls 64 \
  --budget-tokens 2000000 \
  --output-manifest nyu-dev.partial.json
```

For every selected case, staging creates exactly three `thin_scaffold` and
three `ctf_os` challenge identities. Each identity has a fresh `incoming/`
copy, the same public description/prompt and fixed wall allocation, and the
same input manifest digest. Only normalized, release-bound regular files named
by the public `files` array are copied. A `challenge.json` path is always
reserved and rejected even if the source declares it in `files`; private
flag/reference/writeup/solver fields and undeclared files are not copied.
Symlinks, special files, path escapes, dirty source, metadata mismatch,
commit-blob mismatch, oversized input, and any existing destination
state/input/output fail closed. State creation uses create-only semantics under
the ordinary challenge lock. If another operator wins a destination-state race,
staging fails without adopting, resetting, or otherwise changing that state.
The dataset `challenge` label and public `challenge.json.name` are compared
after bounded Unicode NFKC normalization, case-folding, and removal of
non-alphanumeric formatting. This accepts official display-only variants such
as `perfect_secrecy`/`Perfect Secrecy`, while category, repository path, and
release bindings remain exact.

Every fresh input also contains one generated
`nyu_public_metadata.json`. Its canonical JSON object has exactly these public
keys:

```text
case_id category description files name path release_commit
```

This bounded regular file is created with exclusive no-follow semantics before
the engine inventories the input. It binds the public case identity, release,
dataset path, and declared file list into each session digest. In particular,
two service-only cases with `files: []` no longer collapse to the same empty
input digest. No other `challenge.json` key is projected into this file.

The output is a deterministic schema-v2-shaped **partial** manifest. Every
split partial staged from the same release has the same release-level
`benchmark_id`; split membership remains in `splits[].name`, not in that shared
identifier. This lets the operator's explicit full-manifest assembly reject
mixed releases without first rewriting otherwise compatible benchmark
identities. Assembly remains operator-controlled; staging does not invoke a
merger or select another split. The partial manifest includes:

```json
{
  "metadata": {
    "partial_manifest": true,
    "promotion_ready": false,
    "automatic_challenge_start": false,
    "automatic_flag_submission": false,
    "model_visible_external_writeup_or_flag_access": false,
    "source_verifier_may_read_hidden_metadata": true
  }
}
```

This extra metadata deliberately makes `ctfos benchmark freeze` reject the
partial file. It cannot be used for promotion or comparison. The operator must
independently select and stage the required `dev`, `regression`, `blind`, and
`live` memberships, combine them into one complete promotion schema-v2
manifest, verify all case/session/input bindings, remove partial-only metadata,
and then freeze the complete manifest. CTF-OS never invents missing splits or
selects cases.

Fresh staging cannot attest prior engine exposure. Consequently even a
`--split regression` partial manifest records `prior_engine_runs: 0`. Before a
complete regression manifest can be frozen, the operator must replace that
value with a verified positive count backed by the actual cohort history; the
normal promotion parser rejects an unexposed regression split.

Staging does not run any session, and a partial manifest cannot be prepared or
run as promotion evidence. It also does not freeze the wall clock:
`add_challenge` records an absolute deadline when each fresh state is created.
The JSON result therefore prints exact per-session commands for later use.
Only after a complete manifest has been frozen, choose one session and run
them in this order immediately before execution:

```sh
ctfos budget-reset CONTEST CATEGORY CHALLENGE --seconds WALL_SECONDS
ctfos benchmark prepare \
  --manifest FULL_FROZEN_MANIFEST \
  --session SESSION_ID
ctfos solve CONTEST CATEGORY CHALLENGE --mode thin
```

Use `--mode managed` for the corresponding `ctf_os` arm. The budget reset
preserves a clean pre-execution state and re-arms the exact fixed allocation;
preparation still verifies that no run, model session, candidate, submission,
or solve trajectory exists. Add any challenge endpoint only through the
ordinary explicit per-challenge target allowlist before preparation. Starting
services, recording manual outcomes, capturing evidence, and submitting any
candidate remain operator actions.

Cohort creation is create-only but not transactional across all selected
cases. A storage or process failure after some sessions were created leaves
those already-created canonical states and inputs in place and emits no usable
partial manifest. The engine deliberately does not roll back canonical state.
Before retrying, the operator must inspect the exact memberships and either
choose a fresh contest ID or explicitly clean only verified, never-executed
partial destinations.
