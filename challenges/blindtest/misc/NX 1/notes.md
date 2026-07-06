# Challenge Notes

## Summary

- Event: blindtest
- Category: misc
- Name: NX 1
- Status: solved
- Remote: `host3.dreamhack.games:12094`
- Prompt: "Yeah, this is an executable file. But I'm goint to make it so it can't be run."

## Artifacts

- Original handout files were supplied in the challenge root and normalized into `dist/`.
- `dist/server.py`: Python service that accepts base64, validates an uploaded ELF64 x86_64 file has no executable sections or executable program segments, then chmods and runs it.
- `dist/Dockerfile`: Python 3.12.11 slim bookworm image with `socat` on port 31337.
- `dist/flag`: local fake flag placeholder.
- `work/pybytes_preinit_noexec.elf`: final uploaded ELF payload. It has no executable program headers and no section table.
- `work/exploit.py`: sends the base64 payload, waits so `server.py` does not read-ahead buffer the Python script, sends Python code to print `/flag`, then half-closes the socket.
- SHA256:
  - `dist/server.py`: `38eddc34d3af5f4e4582f8829ca4c1108440e4bc85248f2efe0eac6a24f5e5d5`
  - `dist/Dockerfile`: `56c948b7e49faa8007192797688bc53b765c7a3a0ccaa3e62f6a839b9a42db3d`
  - `dist/flag`: `d65522611a74e6a709c6cb61e58c858434d8a570277517b1645fcf8af41a606a`

## Observations

- `server.py` checks ELF magic, 64-bit class, x86_64 machine type, every section header `sh_flags & SHF_EXECINSTR`, and every program header `p_flags & PF_X`.
- If validation passes, the service writes the file to a tempfile, `chmod 755`, then executes it with `subprocess.run([fname], capture_output=True, timeout=5)`.
- The bug surface is a Linux ELF loader/parser mismatch: `server.py` validates declared executable flags but still asks the kernel to execute the file.
- `DT_PREINIT_ARRAY` is run by `ld-linux` for the main executable before control reaches the uploaded ELF entry point.
- A preinit pointer relocated to `libpython3.12.so.1.0` symbol `Py_BytesMain` executes external library code, not uploaded executable pages.
- The final ELF clears all local `PF_X` program-header bits and removes section headers, so `server.py` accepts it.

## Hypotheses

- Solved path: use `DT_PREINIT_ARRAY` to make the dynamic linker call `Py_BytesMain(argc, argv)` from the container's `libpython3.12.so.1.0`; then provide Python source over inherited stdin to read `/flag`.

## Attempts

- 2026-07-06: Read required workspace docs and loaded `ctf-misc`, `ctf-triage`, and `ctf-pwn` guidance.
- 2026-07-06: Normalized misplaced handout files into `dist/`.
- 2026-07-06: Tested and rejected pure non-executable `PT_LOAD` code: local kernel enforces NX and segfaults.
- 2026-07-06: Tested and rejected `PT_INTERP=/bin/sh`, `/bin/cat`, and `/lib64/ld-linux-x86-64.so.2` as direct interpreters; dynamic executables used as interpreters crashed or exited before useful stdin control.
- 2026-07-06: Tested dynamic-loader constructor ideas. Main `DT_INIT_ARRAY` is not enough because it is normally reached through the program's own non-executable startup path.
- 2026-07-06: Found working primitive with main `DT_PREINIT_ARRAY` relocated to `Py_BytesMain`.
- 2026-07-06: Verified payload directly in the pinned Python 3.12.11 slim container with fake `/flag`.
- 2026-07-06: Ran live remote exploit against `host3.dreamhack.games:12094` and obtained `<REDACTED_FLAG>`.
- 2026-07-06: Ran `python3 tools/replay_runner.py --allow-remote-live "challenges/blindtest/misc/NX 1"` successfully.

## Tool Routing Decision

- Primary tools used: `file`, `sha256sum`, Python source audit, `gcc`, `patchelf`, `readelf`, pinned Docker image, socket exploit script, `replay_runner`, `report_sanitize`.
- Considered: radare2 MCP, angr MCP, Playwright MCP, Docker.
- Used: local file inspection, service source audit, ELF header probes, dynamic-loader preinit payload, pinned container verification, live remote replay, sanitizer.
- Skipped: radare2 MCP and angr MCP because generated ELF layout and loader behavior were more directly inspected with source/readelf; Playwright MCP is not applicable; broad pwn gadget tooling was low value after the primitive became dynamic-linker metadata.
- Missing: none.
- Decision summary: Start with misc routing because the supplied path is `misc`; route into pwn/native-loader analysis because the prompt and service center on executing constrained ELF files. Final solution is a loader metadata bypass rather than memory corruption.

## Agent Design Metadata

- Agent mode: assisted
- Failure class: none
- Replay quality: remote-live replay, deterministic payload, saved raw evidence with redacted summaries, proof validation passed.
- Shareability: share metadata, replay script, exploit/generator sources, and redacted summaries/checks; keep raw logs containing the flag local.
- Tool effectiveness: `file` high, `sha256sum` high, local Python high, `gcc` high, `patchelf` medium, Docker high, socket exploit high, sanitizer high, reverse MCP skipped_low_value, Playwright not_applicable.
- Skipped tools/MCP rationale: no compiled challenge binary exists to decompile; the useful artifact is source code plus crafted ELF inputs.

## Blocker or Solve

- Final command: `python3 tools/replay_runner.py --allow-remote-live "challenges/blindtest/misc/NX 1"`
- Flag or proof: live remote printed `<REDACTED_FLAG>`; full flag retained only in raw local logs and the user-facing final response.
- Blocker reason:
- Next action:

## Evidence

- `evidence/remote_raw.log`: first live solve transcript; contains flag and must stay local.
- `evidence/remote_raw.summary.md`: redacted first live solve transcript.
- `evidence/remote_raw.sanitize_check.md`: sanitizer check for first live solve transcript.
- `evidence/replay_20260706T141930Z.log`: replay runner raw log; contains flag and must stay local.
- `evidence/replay_20260706T141930Z.summary.md`: redacted replay summary.
- `evidence/replay_20260706T141930Z.sanitize_check.md`: sanitizer check for replay log.
- `evidence/proof_validate.txt`: final proof-validation result.
