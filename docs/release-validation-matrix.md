# All-category release validation matrix

`scripts/check-all-category-release-matrix.py` is a developer release check.
It is not part of the challenge-solving CLI and does not choose, queue, or
switch challenges. It cannot accept a challenge identity, model setting,
remote target, or submission action.

The runner executes this closed source-controlled gate inventory:

| Gate | Category coverage | Network contract |
| --- | --- | --- |
| Pwn dependency/effect | Pwn D→V→L/N/A→P→one-shot E | `none` |
| Pwn interaction effect | typed RIP-control or canonical executed parent → bounded data-only interaction recipe → attack 3 + matched control 3 | `none` |
| Web state/impact | Web role-separated state and differential impact | ephemeral Docker `--internal` targets |
| Web active probe | Web race 3+3 and OOB 3+3; inspected network and exact target-event audit | ephemeral Docker `--internal` targets |
| Rev accepted input | Rev original-binary positive 3 / negative 3 | `none` |
| Crypto + Misc | managed Builder → operator-preissued hidden Crypto 3+3; managed Misc transform + negative control + 3 replays | `none` |
| Forensic assertion | Forensic indexed, pointer-bound, cross-tool assertion | `none` |

Each child command is fixed in the runner source and receives the same
`sha256:<64hex>` local Docker image ID. The runner refuses a dirty Git tree,
an untracked or modified gate script, a missing image, a child with nonzero
exit status, a missing/negative final gate summary, an image-binding mismatch,
or source/image drift during the run. Model and credential-like environment
variables are removed from child environments.

Child gates do not carry a second hard-coded release digest. Each child
validates and binds the exact `sha256:<64hex>` local image ID supplied by the
parent matrix. The parent is the pin authority: before launching children it
requires that ID to equal `.ctfos/engine.toml` `runtime.image_digest` and that
Docker inspection resolve to the same exact ID. After the children finish it
rechecks the source snapshot, inspected image, and configured pin. A missing or
mismatched pin is refused before execution; later source, image, or pin drift
prevents `ok: true`. The report does not claim a separate configured-pin field.

The Pwn dependency child does not trust stage counters or the child process's
last output line. `1c82147` reloads canonical state, re-reads every bounded
request/result/validation sidecar, committed artifact, and compact effect
transport receipt, and requires exact stage cohorts for six crash, one runtime
snapshot, three IP-control, and six effect executions. Its parent parser uses a
bounded full-stream strict JSON schema and requires three repetitions to have
disjoint run, effect-child, physical-manifest, and sentinel evidence. The
focused Pwn suite passed 69 tests; the pinned image passed one 16/16 proof and
the three-way 48/48 proof with all three tamper controls rejected, network
`none`, and zero candidates/submissions.

The Pwn interaction child accepts no shell program as its interaction
authority. It binds an existing typed RIP-control or canonical executed parent
to a canonical `pwn_local_bounded_interaction_v1` recipe, exact source and
image, an engine preissue, and the attested image producer. Three attacks and
three matched producer-owned controls run in distinct clean network-none
workspaces. The child summary is accepted only when the host evaluator
reconstructs all transcript and derivation-DAG bindings, observes the effect in
all attacks, rejects it in all controls, and confirms that no candidate,
submission, or challenge-status authority was created.
`c9eee37` derives every transport counter from the six physical records instead
of literals. Its focused suite passed 23 tests and the release proof reported
exactly six physical records.

The Web active child inspects the exact Docker network after creation and
requires a matching name with `Internal:true`; printing a literal isolation
claim is not sufficient. Its target log parser consumes a bounded stream of
complete JSON objects, including valid objects written adjacently by concurrent
target threads. Malformed or trailing bytes, non-object JSON, duplicate keys,
non-finite values, and stream/event bound violations fail closed. The release
summary itself is an exact no-extra schema at the root, network, race, OOB, and
target-audit levels. Network inspection was added in `e201e6a`; concurrent log
stream parsing was fixed in `dd929f0`. `cf155cc` additionally reloads canonical
impact state and re-reads the physical request/result/validation sidecars,
artifacts, and receipts, so hostile sidecar rewrites and artifact deletion fail
closed.

The Crypto/Misc child is also an authority-bound release gate. The operator
preissues variant parameters/expected output or the verifier from host files
outside the challenge tree before the Builder run exists. The managed Builder
publishes only the solver/original parameters or transform DAG/tool plus the
opaque preissue ID. The child summary is rejected unless
`oracle_authority=managed_oracle_preissue_v1`, that preissue was consumed
exactly once, and Crypto's declared result is reconstructed from six persisted
physical Run records and their request/result/validation documents. The Python
and Sage paths each require all six clean runs. Misc must complete exactly one
transform, one rejecting negative control, and three verifier replays while
remaining candidate-only. Neither path authorizes a submission. Physical-run
reconstruction was added in `2610c52`.
`d550df15b13b47304872300989e6beeb94c93701` additionally binds every
request/result/validation and stdout/stderr sidecar to the corresponding
physical Run. Its actual pinned-Docker gate completed in 42.122 seconds with
Python 6/6 and Sage 6/6 physical successes, while hostile sidecar and stdout
replacement controls were rejected. This direct child gate still does not
replace the pending final clean-source matrix.

The remaining category release-proof provenance blockers have been closed:

- `3726adb` makes Rev re-read the six terminal sidecars and committed artifacts;
  failed-sidecar rewrites and artifact deletion no longer preserve a pass.
- `c690af0` derives Misc success from physical runs and artifacts; the five
  failed-run and 22-deleted-artifact controls fail closed.
- `7c3d604` makes Forensic re-read physical sidecars/artifacts and requires two
  genuinely distinct implementations: Python `/usr/bin/python3` with SHA-256
  `1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118`
  and Perl `/usr/bin/perl` with SHA-256
  `56e5ea41974eb1eff0f7ea64677578b1938053d29818c2810bcb21e2ca68cafa`.
  Its focused 91 tests and seven pinned-Docker tests passed in 37.961 seconds;
  sidecar/artifact mutation and duplicate-version controls were rejected.
- `5e88071` carries the hardened Pwn and Forensic exact schemas into the
  all-category matrix validator.

These child results are deterministic evidence, but a matrix alone is not the
final release receipt. `scripts/check-release-acceptance.py` binds the full
clean-worktree source suite, strict doctor result, this matrix, and pre/post
source-image-pin-runtime stability into one ignored local unsigned receipt.

After building the release image and committing the exact source under test:

```sh
CTFOS_RELEASE_IMAGE_ID="$(
  docker image inspect --format '{{.Id}}' ctf-os:core
)"
ctfos pin-image
python scripts/check-all-category-release-matrix.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
```

The default is two concurrent top-level gates, bounded to at most three. Pwn
already performs three internal repetitions, so the bound avoids an
uncontrolled Docker fan-out. Use `--jobs 1` for a resource-constrained host.

The command prints a small JSON envelope with an exact `report` pointer and
SHA-256. By default artifacts are placed below the ignored
`.ctfos/release-matrix/` directory. `report.json` records:

- exact source commit and each invoked script hash;
- exact inspected image ID;
- every actual argv, exit code, and duration;
- full-stream SHA-256 and byte count for stdout/stderr;
- bounded stdout/stderr artifact pointers and truncation status;
- the child summary hash and category coverage;
- explicit false values for automatic selection, switching, submission, model
  requests, and remote CTF requests.

Each stored stream is capped at 1 MiB. If a child emits more, the artifact
retains bounded head/tail evidence while the report still hashes and counts
the complete stream. The report itself is capped at 128 KiB. An existing
explicit `--output-dir` is never overwritten.

This matrix proves deterministic local hot paths against one exact container
image. It does **not** prove solve@1, hidden/live solve performance, frontier
model quality, remote portability, or a human-submitted flag. Those remain
separate thin/full and blind/live evaluations; a green local matrix must not
be presented as a competition solve.

An interim run at source `ad6ae43` passed all seven gates and all six
categories against image
`sha256:f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338`.
Its local report is `.ctfos/release-matrix/run-ddz31_yt/report.json`, SHA-256
`ef8e1a8c2c36c689a45d10304e4bd8fe1da629f02e3f766aac03e46f10899570`.
That receipt predates `d550df1`, `dd929f0`, `cf155cc`, `3726adb`, `c690af0`,
`1c82147`, `c9eee37`, `7c3d604`, `5e88071`, and
`d2fb1130b147605ca5d829ff7d20946fb2f3e41f`, so it is historical interim
evidence rather than current-source release acceptance. The latter commit
binds schema-v1 prompt/description/category/incoming/static-source operator
input throughout promotion collection and passed its focused 74/74 tests in
110.727 seconds; it is implementation evidence, not an executed blind/live
cohort or measured solve uplift. That historical run never becomes current by
documentation update. Current `ENGINE_RELEASE_GO` is determined only by the
operator-selected exact local unsigned acceptance receipt described in
[`RELEASE_STATUS.md`](../RELEASE_STATUS.md).
