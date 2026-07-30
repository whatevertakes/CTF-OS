# All-category release validation matrix

`scripts/check-all-category-release-matrix.py` is a developer release check.
It is not part of the challenge-solving CLI and does not choose, queue, or
switch challenges. It cannot accept a challenge identity, model setting,
remote target, or submission action.

The runner executes this closed source-controlled gate inventory:

| Gate | Category coverage | Network contract |
| --- | --- | --- |
| Pwn dependency/effect | Pwn D→V→L/N/A→P→E | `none` |
| Web state/impact | Web role-separated state and differential impact | ephemeral Docker `--internal` targets |
| Web active probe | Web race 3+3 and OOB 3+3 | ephemeral Docker `--internal` targets |
| Rev accepted input | Rev original-binary positive 3 / negative 3 | `none` |
| Crypto + Misc | Crypto metamorphic 3+3 and Misc transform DAG replay | `none` |
| Forensic assertion | Forensic indexed, pointer-bound, cross-tool assertion | `none` |

Each child command is fixed in the runner source and receives the same
`sha256:<64hex>` local Docker image ID. The runner refuses a dirty Git tree,
an untracked or modified gate script, a missing image, a child with nonzero
exit status, a missing/negative final gate summary, an image-binding mismatch,
or source/image drift during the run. Model and credential-like environment
variables are removed from child environments.

After building the release image and committing the exact source under test:

```sh
CTFOS_RELEASE_IMAGE_ID="$(
  docker image inspect --format '{{.Id}}' ctf-os:core
)"
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
