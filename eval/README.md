# Internal evaluation harness

This directory compares receipts from user-opened Sol sessions. It deliberately
does not start Codex, schedule workers, or submit flags. Run the same imported or
locally authored fixture once in `solo` mode and once with the adaptive policy,
save one schema-shaped JSON receipt per run, then execute:

```bash
uv run python eval/run_eval.py eval/results/*.json --output eval/summary.json
```

The summary claims an improvement only when paired observations show a higher
verified solve rate, or the same solve rate with lower median time, context
bytes, or child-agent use.
Public fixtures must include their source and license in their fixture README;
large/copyrighted inputs should be imported locally and remain gitignored.

Fixture families are intentionally small: `misc-trivial`, `pwn-basic`,
`pwn-libc`, `web-source`, `web-compose`, `rev-basic`, `crypto-basic`, and
`forensic-basic`. A fixture directory contains metadata and may contain locally
authored challenge files or an `IMPORT.md` recipe.
