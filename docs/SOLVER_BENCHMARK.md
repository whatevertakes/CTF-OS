# Solver benchmark contract

This harness prepares and evaluates a preregistered matched experiment. It never launches a model, starts or stops a native Sol/child session, submits a flag, or treats unit, policy, and integration tests as solve-performance evidence. Passing those tests is not evidence of improved solve performance. Until controlled runs exist, plain Sol versus CTF-OS is `INCONCLUSIVE`.

## Frozen treatments

| Arm | Treatment | Child contract |
|---|---|---|
| A | plain Sol | User-opened Sol session, no CTF-OS race/scheduler/event-management prompt, child, replacement, or control action |
| B | CTF-OS `sol-only` | Scope, sandbox, receipts, verification and telemetry; zero children |
| C | CTF-OS `fixed-race` | Sol plus exactly three frozen category-template intents, no width change/replacement, maximum concurrency 4 |
| D | CTF-OS `adaptive-race` | Sol starts alone, 60–90 second bounded observation, 0–3 distinct mechanisms, one plateau/refutation replacement, maximum concurrency 4 |

Compatibility vocabulary in older fixtures called these `plain Sol xhigh CLI`, `current CTF-OS Sol-only`, `CTF-OS fixed race`, and `CTF-OS evidence-driven race`; the authoritative D treatment name is now `adaptive-race`.

Arm C is invalid if any of its three child lanes fails to reach lineage `RUNNING`; it must be an environment failure or invalid matched block, not a quiet Sol-only run. Arm D may continue Sol-only after a recorded branch start failure in live competition. Tier is never accepted as a benchmark treatment definition.

All arms use the same exact candidate Git commit, clean worktree, challenge/target snapshot, transformation and matched seed family, content-addressed target/tool image digests, requested model policy, host envelope, 2700-second limit, and network profile: local replay, 30 ms RTT, 0.1% loss, 100 Mbit/s, identical DNS and outbound-deny policy.

## Preregistration lock and attempts

`BENCHMARK_LOCK.json` and detached `BENCHMARK_LOCK.sig` live outside challenge output. The signature binds the canonical schedule digest and preregistered randomization seed as well as the arm configuration. Execution rejects a symlink, writable or non-canonical lock, unsigned/invalid Ed25519 signature, non-40-hex commit, dirty worktree, mutable or locally unresolved image identity, archive/CLI/schedule/configuration/snapshot mismatch, a host below 16 vCPU/64 GiB/200 GiB free SSD or non-Linux/amd64 Docker, and credential or personal-host-path material. The private signing key is never copied into the repository or output.

Each schedule entry gets a fresh `attempt_id` derived from matched block, arm, repetition and preregistered seed. `run_id` binds that attempt to the deterministic `challenge_instance_id`. Benchmark commands return the exact run and never read or publish `ACTIVE_RUN`. No prior ledger, artifact, evidence, model context, sandbox/container, port, cache, or generated solver file is reused.

`RUN_MANIFEST.json` records requested and independently observed runtime identity, exact source/image/CLI/host/Docker/network identity, all milestone timestamps with null reasons, oracle/censor/environment/terminal outcome, explicit resource observation status, and attempt-bound target-health intervals. Missing external model telemetry remains `NOT_OBSERVABLE`, never zero and never copied from requested values. A direct-argv deterministic host monitor records run-start, every-60-second, and run-end health receipts without creating model sessions.

## Deterministic schedule

Twelve snapshots × four arms × three repetitions produce 144 entries. Each `matched_block_id` binds one challenge instance, repetition and matched seed. The preregistered randomization seed deterministically shuffles A/B/C/D inside each block. Cross-arm simultaneous execution inside a block is rejected. Private-heldout provenance is omitted from solver context while its digest binding remains.

```bash
uv run python -m ctf_os.agent_tools benchmark-schedule-create \
  --challenges-json '<12 frozen snapshot records>' \
  --randomization-seed '<preregistered-seed>' --output prereg/SCHEDULE.json

uv run python -m ctf_os.agent_tools benchmark-start '<selector>' --contest '<contest>' \
  --schedule prereg/SCHEDULE.json --entry-id '<entry-id>' \
  --lock prereg/BENCHMARK_LOCK.json --signature prereg/BENCHMARK_LOCK.sig \
  --public-key '<public-key.pem>' --key-id '<key-id>' \
  --challenge-archive '<frozen-challenge-archive>' \
  --target-image-digest 'sha256:<64hex>' --tool-image-digest 'sha256:<64hex>'
```

The user opens the model session from the returned context. Target health and resource commands take exact `--run-id`. `benchmark-health-monitor` runs direct argv at start, every 60 seconds, and end. `benchmark-telemetry-monitor` samples explicitly named process trees, a dedicated network namespace, and exact container identities without controlling their lifecycle. Runtime identity and any externally supplied model telemetry use `benchmark-runtime-observation-record` and `benchmark-resource-record`; missing values require an explicit status/reason and are never written as zero. `benchmark-outcome-record` binds the oracle and terminal evidence, then `benchmark-complete` validates health cadence, deterministic telemetry, required runtime observation, Arm treatment, and appends the schedule completion receipt. This patch does not execute the 144 runs.

## Authoritative evaluation

`eval/run_eval.py` requires complete A/B/C/D matched blocks. Duplicate attempt/run identity, `ACTIVE_RUN` selection, cross-run artifact reuse, lock/signature failure, snapshot mismatch, insufficient target health, identity/telemetry missingness, or target failure invalidates and reports the block. Unsolved attempts remain at 2700-second censoring; missing latency is excluded only from that latency metric and is never imputed.

Primary outputs include oracle-accepted solve rate, first valid flag and executed working-PoC time, RMST, solved-only median, p90/maximum resolved latency, false/scope/denied-action counts, terminal correctness, resources, and target/model/environment failure duration. Comparisons use matched blocks, exact McNemar discordance, paired time/resource differences, paired RMST/median, and a fixed-seed challenge-cluster bootstrap that retains all repetitions of a sampled challenge.

Diagnostic mechanism fields remain available for time-to-first-viable-hypothesis, time-to-working-PoC, time-to-first-remote-attempt, time-to-flag, commands before first PoC, research-drift events, hypothesis kill latency, branch replacement count, false flags, strict replay success, and run-to-run variance. They cannot replace the primary oracle/censoring analysis.

`PRIVATE_HELDOUT` is the primary conclusion, `TRANSFORMED_FAMILY` secondary evidence, `PUBLIC_KNOWN` diagnostic only, and `LIVE_CONTEST` excluded from controlled conclusions. Compatibility display labels are `private-heldout`, `transformed-family`, `public-known`, and `live-contest`. Each B/C/D arm is compared with A and with one another.

`PROVEN_IMPROVEMENT` requires every preregistered private-heldout guardrail: solve-rate CI lower bound at least −5 percentage points; at least 15% median or RMST flag-time improvement; paired CI favorable and excluding zero; no false-flag or scope-violation increase; 100% terminal correctness; complete resource reporting; and latency not explained only by target/model queue variation. Non-inferior solve rate with time CI crossing zero is `SUGGESTIVE_ONLY`. Missing/incomplete/wide evidence is `INCONCLUSIVE`; solve regression beyond five points or material uncompensated slowdown is `REGRESSION_INDICATED`. Cost, token, child, context, event, artifact, management-message, or utility-score changes alone can never prove improvement.
