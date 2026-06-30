# Level 4 Self-Test Benchmark

The Level 4 self-test verifies that the interface layer is connected to the
existing Level 1, Level 2, and Level 3 contracts.

Run:

```bash
python3 benchmarks/level4_selftest.py
```

The benchmark checks that:

- `tools/preflight_check.py` recognizes the Level 4 files.
- A challenge created through `tools/intake_challenge.py` can be initialized by
  `tools/level3_orchestrator.py`.
- `tools/level4_interface.py build` writes
  `work/LEVEL4_INTERFACE.json` and `work/LEVEL4_STATUS.md`.
- The manifest includes Level 1 config, Level 2 state/proof/replay paths, and
  Level 3 board artifacts.
- The web-category browser surface detects configured Playwright MCP support.
- `state.json.metadata` receives Level 4 manifest and report pointers.
- `doctor` and `status` operate against the generated interface view.
