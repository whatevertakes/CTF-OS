# Challenge Notes

## Summary

- Event: blindtest
- Category: misc
- Name: NX 1
- Status: solved
- Remote: `host8.dreamhack.games:16487`
- Prompt: executable upload service that rejects executable ELF sections or segments, then runs accepted files.

## Artifacts

- `dist/NX 1.zip`: original handout archive.
- `dist/server.py`: service source copied from the handout.
- `dist/Dockerfile`: container definition copied from the handout.
- `dist/flag`: handout flag placeholder copied from the handout.
- `work/build_payload.py`: pure-Python ELF generator for replay.
- `work/solve.py`: remote TCP replay client.
- `work/payload.bin`: generated ELF payload.
- `work/payload.b64`: base64 payload sent to the service.
- `work/readelf_payload.txt`: payload ELF/program-header inspection.
- `work/objdump_payload.txt`: syscall payload disassembly.
- `work/server_check.txt`: local result from the handout `server.check()`.

## Observations

- `server.py` validates ELF64/x86_64 magic and machine fields.
- Section validation is skipped when `e_shoff == 0`.
- Program-header validation is skipped when `e_phoff == 0`.
- Linux still accepts `e_phoff == 0` and reads a program-header table starting at file offset zero.
- By setting `e_phnum = 3`, the first two entries are harmless overlapped data and the third entry at file offset `112` is a valid executable `PT_LOAD`.
- The service checker returns `None` for the generated payload, while `readelf` sees the hidden `RWE` `LOAD` segment.

## Hypotheses

- Initial hypothesis: an ELF without `PT_GNU_STACK` might trigger `READ_IMPLIES_EXEC`, allowing readable non-`PF_X` code to execute. This passed the checker but segfaulted locally.
- Working hypothesis: use the parser mismatch around `e_phoff == 0` to hide the real executable segment from the Python checker while keeping it visible to the kernel.

## Attempts

- Reviewed `server.py` and confirmed all validation is structural; no sandbox beyond timeout.
- Built a one-segment `PF_R|PF_W` ELF with no section table and no `PT_GNU_STACK`; it passed `server.check()` but exited with SIGSEGV locally.
- Rebuilt the ELF with `e_phoff = 0`, `e_phnum = 3`, no section table, and a real `PF_R|PF_W|PF_X` `PT_LOAD` at the third program-header slot.
- Verified the rebuilt payload passes `server.check()` and executes locally.
- Direct remote probe against `host8.dreamhack.games:16487` returned a flag-like marker; the raw direct-probe transcript was removed in favor of replay-runner evidence.

## Tool Routing Decision

- Primary tools used: `python3`, `readelf`, `objdump`, raw TCP socket, `replay_runner`, `proof_validate`.
- Considered: ctf-misc routing, manual ELF generation, `.codex/bin` radare2 MCP wrapper, `.codex/bin` angr MCP wrapper, Playwright, Burp.
- Used: local source review, generated ELF probes, `server.check()` import, `readelf`/`objdump`, TCP replay client.
- Skipped: radare2 MCP and angr MCP because there was no opaque target binary to reverse or symbolically execute; Playwright and Burp because the challenge path is a TCP ELF runner rather than browser or HTTP behavior.
- Missing: none.
- Decision summary: local evidence was sufficient to identify a parser/kernel ELF interpretation mismatch; MCP tooling was not materially useful for this source-provided challenge.

## Blocker or Solve

- Solve: `work/build_payload.py` constructs an ELF where `e_phoff == 0` makes the Python checker skip program-header validation, but Linux still scans three phdr slots from offset zero and executes the third `PF_R|PF_W|PF_X` `PT_LOAD`.
- Final command: `python3 tools/replay_runner.py --allow-remote-live 'challenges/blindtest/misc/NX 1'`.
- Proof scope: live remote replay against `host8.dreamhack.games:16487`; raw replay contains the flag-like marker and the summary redacts it.

## Evidence

- `evidence/replay_20260701T050059Z.log`: raw live replay transcript, contains sensitive flag material.
- `evidence/replay_20260701T050059Z.summary.md`: redacted replay summary.
- `evidence/replay_20260701T050059Z.sanitize_check.md`: redacted sanitizer-check output generated with `--check`.
- `evidence/proof_validate.txt`: saved proof validation output.
