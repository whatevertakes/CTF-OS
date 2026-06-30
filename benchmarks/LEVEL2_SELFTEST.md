# Level 2 Self-Test Benchmark

The Level 2 self-test verifies the local intake, replay, redaction summary, and
proof-validation path with no external dependencies.

Run Level 0/1/2 preflight first when checking a restored or modified
workspace:

```bash
python3 tools/preflight_check.py
```

Run from the workspace root:

```bash
python3 benchmarks/level2_selftest.py
```

The benchmark creates the acceptance challenge paths, verifies the contract, and removes only directories marked as self-test artifacts. To inspect the generated tree after the run:

```bash
python3 benchmarks/level2_selftest.py --keep
```

Manual smoke test:

```bash
python3 tools/intake_challenge.py --event _selftest --category misc --name dummy
python3 tools/replay_runner.py challenges/_selftest/misc/dummy
python3 tools/proof_validate.py challenges/_selftest/misc/dummy
```

Expected result:

- challenge files exist under `challenges/_selftest/misc/dummy`
- new challenges include `state.json`, `notes.md`, `replay.sh`, `evidence/`, `dist/`, and `work/`
- at least one `evidence/replay_*.log` file exists
- every replay run creates a matching `evidence/replay_*.summary.md`
- replay summaries redact flag-like markers
- `state.json` evidence entries are updated with replay logs and summaries
- proof validation passes for the default `new` status
- new `state.json` files include `proof_scope`, `remote_status`,
  `remote_solve`, `replay_kind`, `current_remote_liveness`, and
  `evidence_sensitivity`
- proof validation rejects `blocked` without a blocker reason
- proof validation rejects `solved` without a non-empty `final_command`,
  replay evidence, and a non-`none` proof scope
- `partial` validates only when it has evidence or a blocker reason
- `partial` and `new` challenges validate structurally but are not reported as solved
- `replay_kind=remote_live_exploit` is blocked unless replay is explicitly run
  with `--allow-remote-live`
