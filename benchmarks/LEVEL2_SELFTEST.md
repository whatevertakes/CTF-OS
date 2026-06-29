# Level 2 Self-Test Benchmark

The Level 2 self-test verifies the local intake, replay, and proof-validation path with no external dependencies.

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
- proof validation passes for the default `new` status
- proof validation rejects `blocked` without a blocker reason
- proof validation rejects `solved` without both a non-empty `final_command` and replay evidence
- `partial` and `new` challenges validate structurally but are not reported as solved
