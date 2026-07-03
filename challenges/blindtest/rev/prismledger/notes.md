# Prismledger

## Summary

- Event: blindtest
- Category: rev
- Name: prismledger
- Status: solved
- Remote: `host3.dreamhack.games:23808`
- Handout: stripped x86-64 PIE ELF plus local `flag` file.
- Solve: recovered the 60-character accepted input from the binary checker, then replayed it against the live remote service. The remote returned `correct!` and a flag-like proof; raw flag content is present only in raw evidence logs and redacted in summaries.

## Artifacts

- `dist/chall`: original ELF handout, SHA-256 `0a9d7d3a7bc6ac8efc707f8cafebbb30fbf2094b9950a346e8370a9b9b4ef69d`.
- `dist/flag`: original local flag stub, SHA-256 `af7a5b59a578ff9675380e0535a090d22abbb007053a1067f5a553168615973c`.
- `work/file.txt`: saved `file dist/*` output.
- `work/sha256sum.txt`: saved handout hashes.
- `work/checksec.txt`: saved protection summary.
- `work/embedded_digests.txt`: 20 embedded 64-hex-character target digests.
- `work/r2_checker_disassembly.txt`: radare2 disassembly of `main` and checker helpers.
- `work/solve.py`: deterministic solver and local/remote replay helper.
- `work/download_metadata/`: moved Windows `Zone.Identifier` sidecar metadata; not part of the challenge handout semantics.

## Observations

- `dist/chall` is a stripped ELF64 PIE dynamically linked to libc; protections include Full RELRO, stack canary, NX, PIE, SHSTK, and IBT.
- The binary reads input with `%4095s`, requires exact length `0x3c` (60), and allows only `0-9`, `a-f`, and `-`.
- `main` processes the input as 20 independent 3-byte chunks.
- For each chunk, the binary applies an index-dependent byte permutation/arithmetic transform, computes a SHA-256-style digest, applies a second index-dependent 32-byte mutation, and compares the result with one embedded target digest.
- On success, `fcn.00002101` prints `correct!` and streams `./flag`.

## Hypotheses

- Confirmed: the 20 long hex strings are comparison digests. `fcn.00002031` parses them into 32-byte buffers from ASCII hex.
- Confirmed: the hash implementation is SHA-256-compatible. The IV constants at `0x3700` match SHA-256 initial state, and Python `hashlib.sha256` reproduces accepted chunks once surrounding transforms are modeled.
- Confirmed: chunk checks are independent, making exhaustive search over `17^3` candidates per chunk practical.
- Falsified: this was not a pwn exploit despite the DreamHack "system hacking" wording. No memory corruption primitive was needed; the checker is pure reverse engineering.
- Falsified: browser/Burp workflow was unnecessary despite the HTTP URL. The useful service was the TCP binary checker.

## Attempts

- Ran workspace intake normalization and moved original handouts under `dist/`.
- Collected `file`, `sha256sum`, `strings`, `readelf`, `checksec`, and local run behavior.
- Used radare2 MCP for initial function discovery and targeted disassembly.
- Used local radare2 CLI to save checker disassembly for durable evidence.
- Implemented `work/solve.py` with:
  - input alphabet check,
  - chunk permutation/arithmetic transforms from `fcn.00001d1f`, `fcn.00001d70`, `fcn.00001dc1`, and `fcn.00001e3a`,
  - SHA-256 digest via Python `hashlib`,
  - digest mutation from `fcn.00001eb4`,
  - comparison against digests extracted from the binary.
- Verified locally with `/lib64/ld-linux-x86-64.so.2 ./chall` because the original handout binary is not executable on disk.
- Replayed remotely with the recovered input:
  `4c731861a6-4ad67-c989af936c7-5aad78c8-9bafc-ddb0141b19-1e3ad`

## Tool Routing Decision

- Primary tools used: radare2 MCP, radare2 CLI, Python `hashlib` solver, `tools/report_sanitize.py`, `tools/replay_runner.py`, and `tools/proof_validate.py`.
- Considered: local ELF triage, radare2 MCP, radare2 CLI, angr symbolic execution, Playwright/Burp, Python brute force.
- Used: `file`, `sha256sum`, `strings`, `readelf`, `checksec`, `mcp__radare2.open_file`, `mcp__radare2.analyze`, `mcp__radare2.list_functions`, `mcp__radare2.disassemble`, `r2`, `work/solve.py`, workspace replay/sanitize/validation tools.
- Skipped: angr, because concrete 3-byte chunk bounds made symbolic execution unnecessary; Playwright and Burp, because no web/browser behavior was involved; Ghidra, because radare2 provided sufficient evidence.
- Missing: the loaded angr MCP tool set exposed decompile/query tools but not an obvious project-open/create tool during this run; it was not needed.
- Decision summary: local static evidence reduced the challenge to independent 3-byte digest preimage searches over a 17-symbol alphabet, so a small deterministic Python solver was the simplest replayable path.

## Blocker or Solve

- Solved.
- Final replay command:
  `python3 tools/replay_runner.py challenges/blindtest/rev/prismledger --allow-remote-live`
- The replay invokes:
  `python3 work/solve.py --remote-host host3.dreamhack.games --remote-port 23808`
- Remote status: live at replay time; replay log includes `remote_liveness=live`.

## Evidence

- `evidence/remote_proof.raw.log`: first raw remote transcript containing the flag-like proof.
- `evidence/remote_proof.raw.summary.md`: sanitized summary of first raw remote transcript.
- `evidence/proof_validate.txt`: saved `tools/proof_validate.py` success output.
- `evidence/replay_20260630T162732Z.log`: canonical replay-runner raw transcript containing the flag-like proof.
- `evidence/replay_20260630T162732Z.summary.md`: sanitized replay summary with `<REDACTED_FLAG>`.
