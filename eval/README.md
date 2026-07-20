# Matched A/B/C/D evaluator

`run_eval.py` is a receipt-only evaluator. It never starts a model, worker, target, or flag submission. Authoritative input is one complete `RUN_MANIFEST.json`-shaped JSON document per A/B/C/D attempt, grouped by `matched_block_id` and repetition:

```bash
uv run python eval/run_eval.py eval/results/*.json \
  --bootstrap-seed 20260720 --bootstrap-iterations 10000 \
  --output eval/summary.json
```

The report validates identity, signed-lock status, target health, explicit telemetry missingness, terminal correctness, censoring, and artifact isolation before matched analysis. It emits validation/exclusion and missingness tables, arm/stratum outcomes, paired McNemar and challenge-clustered bootstrap intervals, RMST/median/tail/resource comparisons, failure duration, and exact preregistered decision checks. Private-heldout is primary; public-known is diagnostic and live-contest is separate.

Legacy `solo`/`adaptive` fixtures remain readable only through compatibility mode and are not authoritative performance evidence. Public fixtures must include source/license metadata; large or copyrighted inputs stay locally imported and gitignored.
