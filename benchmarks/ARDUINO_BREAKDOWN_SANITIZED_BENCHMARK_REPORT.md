# Arduino_Breakdown Sanitized Benchmark Report

## Scope

- Event: blindtest
- Category: pwn
- Challenge: Arduino_Breakdown
- Workspace: challenges/blindtest/pwn/Arduino_Breakdown
- Status: blocked
- Remote replay scope: liveness only

## Challenge Summary

The handout is a Dockerized xinetd service that accepts an Intel HEX file, writes it as user firmware, and executes a patched simavr `simduino.elf`. The useful native primitive is an unchecked host `memcpy()` into `avr->flash + boot_base`, controlled through the supplied HEX file.

## Preserved Evidence

- Original archive copied to `dist/`.
- Extracted handout and helper probes kept under `work/`.
- Remote-matching patched simavr source and Docker build artifacts kept under `work/`.
- Replay evidence recorded under `evidence/`.
- Raw flag-like material is intentionally omitted from this benchmark report.

## Hypothesis Outcome

- Direct out-of-bounds writes are real and can corrupt or crash the simulator.
- The crash-triggered GDB stub was not reachable through the provided host mapping.
- A high-base atmega2560 stack target was falsified by container ASLR sampling.
- Simple heap grooming did not place flash below `avr` under the glibc 2.35 allocation behavior.
- Reusing reachable IRQ hooks remains the most plausible route, but a replay-stable exploit needs a leak or pointer-preserving technique.

## Blocker

The current primitive is contiguous. To keep valid AVR code, the first executable chunk must start near the end of flash, which overwrites intervening simulated memory and heap structures before reaching useful hook fields. A partial overwrite to libc `system()` is not replay-stable because the relevant low address bytes vary under ASLR. The smallest next action is to find a same-library leak or output primitive through an existing callback.

## Benchmark Findings

- The challenge Dockerfile clones upstream simavr without pinning a commit; reproducing the remote required recovering a historical commit from source behavior. This is a challenge-level reproducibility finding, not a verified category-agnostic workspace bug.
- The local Docker credential helper prevented pulling the exact original base image, so a local glibc-matching image was used for analysis. This is an environment finding, not a framework change request.
- The existing architecture handled a blocked, evidence-backed pwn case without redesign: intake, state, notes, replay, proof validation, and corpus evaluation all remained usable.

## Sanitization

This report must not include raw flags, secrets, or replay output containing sensitive markers. It is intended to be sanitized with `tools/report_sanitize.py` before inclusion in `benchmarks/`.
