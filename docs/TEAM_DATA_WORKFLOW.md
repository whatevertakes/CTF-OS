# Team Data Workflow

The repository goal is to collect comparable CTF solve data that can guide
Level 3 agent design. Team members should submit sanitized challenge data, not
framework changes.

## Branches

`main` is owner-controlled. Team members work on data branches:

```bash
git switch -c data/<github-user>/<challenge-or-run-id>
```

Commit only approved data files:

```text
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
benchmarks/*_DATA_MANIFEST.json
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
challenges/<event>/<category>/<challenge>/evidence/*.sanitize_check.md
```

Do not commit raw flags, raw replay logs, private keys, `.env` files, challenge
`work/` scratch trees, dependency checkouts, or framework files.

## Local Validation

Before opening a PR:

```bash
python3 tools/validate_data_submission.py --base origin/main
python3 tools/evaluate_corpus.py
```

For staged files only:

```bash
python3 tools/validate_data_submission.py --staged
```

## Pull Requests

Open a PR from the data branch to `main`. The data-submission GitHub Action
checks that the PR only changes approved sanitized data paths. Owner review is
still required before merge.

If branch push is unavailable, use the benchmark data issue template and attach
the same sanitized files.
