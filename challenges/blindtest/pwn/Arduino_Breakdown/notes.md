# Challenge Notes

## Summary

- Event: blindtest
- Category: pwn
- Name: Arduino_Breakdown
- Status: blocked
- Remote: `nc host3.dreamhack.games 24333` (host port 24333 -> container port 31337/tcp)

## Artifacts

- Original handout: `dist/Arduino_Breakdown.zip`
- SHA-256: `37e41d3d2893b986cddacf4249f264acc27cc290407c0ae7fb3970889b348d15`
- File type: Zip archive data, compression method=store.
- Extraction for analysis will live under `work/`.
- Extracted archive inventory under `work/extracted/`: `flag`, `run.sh`, `Dockerfile`, `xinetd`, `diff.patch`, `libc.so.6`.
- Extracted libc SHA-256: `568740b06a8afa26db4874f8cf61985ecbc6dd127f4229416fe95da8f9ec13fb`.
- Upstream source cloned under `work/simavr`.
- Patch preimage commit found in upstream history: `71c616de2b4b8cd55188b7d888baa47fef75397e` (`2024-11-20`, `Update ADC data register before IRQ calls`).
- Remote-matching source worktree: `work/simavr_202305` at `05b624ddf6b131fc8e8af330c9defaf7ca76d781` with `diff.patch` applied.
- Remote-matching local image: `arduino-breakdown-analysis:local`, built from local Ubuntu 22.04/glibc 2.35 base image `pwn-runtime-9616bf81c70e:latest`.
- Exported remote-matching artifacts: `work/pinned_build/simduino.elf` and `work/pinned_build/libsimavr.so.1`.
- Exported `simduino.elf` SHA-256: `a103c9b9a630990e344a26c8143380143951a5a32cab7875993617ce6e42c8f4`.
- Exported `libsimavr.so.1` SHA-256: `22dcf6b48275689707fc6128de07cc408d7a7489d35760de7846c697df93e18d`.

## Observations

- 2026-06-30T08:15:18Z: Challenge workspace created with `tools/intake_challenge.py --event blindtest --category pwn --name Arduino_Breakdown`.
- 2026-06-30T08:15:46Z: Original supplied zip copied into `dist/`; hash recorded above.
- 2026-06-30T08:16:xxZ: Archive contents list a Dockerized xinetd service on port 31337. `run.sh` kills existing `simduino`, receives a user-supplied hex file for 2 seconds into `./user.hex`, then runs `timeout 60 ./simduino.elf ./user.hex`.
- 2026-06-30T08:17:xxZ: Current upstream `simavr` HEAD (`f44723e8c42431136d5b4de81f789ded56d7e8fa`) does not accept `diff.patch`; the patch preimage matches commit `71c616de2b4b8cd55188b7d888baa47fef75397e`.
- Challenge-level benchmark finding: the provided Dockerfile clones `simavr` without pinning a commit, so fresh rebuilds are not reproducible unless the patch preimage commit is recovered from history. This is not yet a category-agnostic workspace bug.
- 2026-06-30T08:20:xxZ: `work/min_sleep.hex` runs locally and remotely. Remote output includes `atmega328p booloader`, matching 2023-era source rather than later typo-fixed source.
- 2026-06-30T08:24:xxZ: `simduino.c` in `work/simavr_202305` directly executes `memcpy(avr->flash + boot_base, boot, boot_size)` after `avr_init()`; the library helper `avr_loadcode()` has a bounds check but is not used on this path.
- 2026-06-30T08:27:xxZ: Local Docker pull of the original Ubuntu digest failed because Docker credential helper returned `A specified logon session does not exist`. A local glibc-matching pwn-runtime image was used instead; this is a local environment benchmark finding, not a framework bug.
- 2026-06-30T08:30:xxZ: The pinned analysis image reproduces the remote `booloader` banner and uses Ubuntu glibc 2.35.
- 2026-06-30T08:32:xxZ: In the glibc 2.35 image, low-base atmega328p layout has `avr->data` immediately after `avr->flash` at a `0x80010` delta. Overflow from flash can corrupt simulated SRAM and heap metadata after the flash chunk.
- 2026-06-30T08:33:xxZ: High-base atmega2560 layout places mmaped flash below libc/libsimavr/ld mappings, but the atmega2560 threshold forces `dest_min=flash+0x02000001`, above those mappings. ASLR samples put the stack more than 4GB above flash, outside the 32-bit base range.
- 2026-06-30T08:34:xxZ: While a remote crash session was alive, `host3.dreamhack.games:1234` refused connections; the crash-triggered GDB stub is not externally exposed through the provided mapping.
- 2026-06-30T08:40:xxZ: Heap grooming with additional HEX chunks can influence allocation layout, but glibc services the smaller MCU allocation from the older flash-sized freed chunk, leaving `flash` above `avr`. This blocks the simple `avr->run`/`custom.deinit` partial-overwrite route.
- 2026-06-30T08:45:xxZ: Existing IRQ hooks after normal initialization are reachable by overflow at stable offsets (`irq22=flash+0x9600`, `hook22=flash+0xe760`, `hook22.notify=flash+0xe778`). However, the first HEX chunk is contiguous: starting near the end of flash to keep AVR code valid overwrites all intervening data/heap objects, including heap pointers needed to preserve or redirect the hook cleanly.
- 2026-06-30T08:48:xxZ: A 3-byte partial overwrite from a libsimavr hook to libc `system()` needs the randomized low 24 bits of libc. Container samples show `system()` low 24 bits vary between runs, so this path needs a leak or brute force that is not replay-stable.
- 2026-06-30T08:52:36Z: Generated simulator flash dumps were moved under `work/` to keep temporary analysis artifacts inside the challenge-local work area.
- 2026-06-30T08:52:36Z: Added the blocked challenge to `benchmarks/corpus.yaml` as a pwn holdout and drafted a sanitized benchmark report source under `work/`.
- 2026-06-30T08:53:42Z: Re-ran `tools/replay_runner.py`; fresh remote-liveness evidence was generated under `evidence/`.
- 2026-06-30T08:54:12Z: Generated `benchmarks/ARDUINO_BREAKDOWN_SANITIZED_BENCHMARK_REPORT.md` with `tools/report_sanitize.py`.
- 2026-06-30T08:54:12Z: `tools/proof_validate.py` accepted the blocked milestone with two replay logs, no sensitive logs, and live remote-liveness metadata.
- 2026-06-30T08:54:12Z: `tools/evaluate_corpus.py` returned `READY_WITH_CAVEATS`; caveats are existing planned placeholder paths, with no solved-evidence, blocked-reason, or proof-validation failures.
- 2026-06-30T08:54:12Z: `tools/regression_check.py` returned `PASS`.

## Hypotheses

- H1: The handout likely contains a native service binary or firmware-facing emulator component because the category is pwn and the title mentions Arduino. Needs archive extraction and binary triage.
- H2: The remote service speaks a custom serial/Arduino-style protocol on TCP 31337 behind the DreamHack host port. Needs local behavior and remote banner checks before exploit design.
- H3: The exploitable surface may be the host `simduino.elf`/`libsimavr.so` parsing or simulating attacker-controlled Intel HEX, not a conventional included challenge binary, because the service directly executes a simulator against user-controlled firmware.
- H4: If attacker-controlled AVR firmware can influence the `uart_pty` path, GDB stub, persistent flash file, or simulator crash handling, it may provide a host-side file read or code execution path to `/home/arduino/flag`.
- H5: The direct `memcpy()` from user-controlled HEX into `avr->flash + boot_base` is the primary native memory-corruption primitive. It is valid as a host write primitive, but current evidence only proves corruption/crash, not code execution.
- H6: High-base atmega2560 might target the host stack if the mmap/stack delta is below 4GB. Container ASLR sampling falsified this for normal layouts: observed deltas were all above 4GB.
- H7: The crash-triggered GDB stub might be reachable remotely on port 1234. Remote check while a crash session was alive falsified this for the provided DreamHack mapping.
- H8: Multi-chunk heap grooming might place `flash` below `avr`, allowing same-module partial overwrites of `avr->run` and `custom.deinit`. Empirical glibc 2.35 allocation behavior falsified the simple version of this route.
- H9: Normal-layout overflow can target existing IRQ hooks and redirect a callback to libc `system()`. This remains plausible locally, but a remote-stable exploit needs either a heap/libc leak or a sparse/pointer-preserving write; neither has been found.

## Attempts

- Keep payloads, commands, and failed assumptions that shaped the solve path.
- Built patched upstream source at `71c616de...`; it works locally but did not match the remote banner because the remote still contains the `booloader` typo.
- Created `work/simavr_202305` at `05b624dd...` and applied `diff.patch`; source matches the remote banner. Host build failed without `libelf-dev`, so a Docker analysis image was built.
- Created `work/min_sleep.hex`; local and remote executions terminate cleanly and prove the input/replay path.
- Created `work/oob_7f00_300.hex` and `work/crash_7fff_40.hex`; these trigger simulator crash/hang behavior but no flag disclosure.
- Created `work/break.hex`; it keeps a remote crash session alive, but the GDB port remains closed externally.
- Created `work/gen_groom_hex.py` and `work/groom_probe.hex`; confirmed the direct `avr` struct overwrite route is blocked by glibc allocation choice.
- Created GDB probes under `work/` for heap layout, hook enumeration, library deltas, and target offsets.

## Tool Routing Decision

- Primary tools used: `docker`, `gdb`, `python3`, AVR toolchain.
- Considered: `radare2` MCP and `angr` MCP are retrospective inferences only, based on the final evidence trail.
- Used: Docker build/runtime probes, GDB heap and callback probes, Python HEX/payload generators, AVR compile/inspection tools.
- Skipped: `radare2` MCP and `angr` MCP. Retrospective reason: source/debug info plus Docker/GDB probes were higher value than MCP for this dynamic heap/ASLR blocker.
- Missing: none recorded for routing; required AVR toolchain dependencies are tracked separately in `state.json` metadata and `benchmarks/corpus.yaml`.
- Decision summary: MCP non-use is not live-session evidence. The recorded MCP skip is a retrospective observability note so future evaluation can distinguish deliberate CLI-first probing from missing routing data.

## Blocker

- Reason: No ASLR-independent exploit path is available yet. The confirmed primitive is a contiguous write from the first loaded HEX chunk; using it for valid AVR code requires starting near the end of flash, which overwrites intervening heap structures and destroys pointer fields unless a heap/libc leak or pointer-preserving technique is found.
- Smallest next action: find a leak primitive from an existing libsimavr callback, likely by redirecting a reachable hook to a same-library logging/printing function without needing an absolute heap pointer.

## Solve

- Final command:
- Flag or proof:

## Evidence

- Replay logs live in `evidence/`.
- Sanitized benchmark report: `benchmarks/ARDUINO_BREAKDOWN_SANITIZED_BENCHMARK_REPORT.md`.
