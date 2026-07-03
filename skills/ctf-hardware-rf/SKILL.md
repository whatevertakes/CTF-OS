---
name: ctf-hardware-rf
description: Analyze hardware, RF, SDR, signal, and physical-layer CTF artifacts from recorded evidence.
---

purpose: Analyze hardware, RF, SDR, signal, and physical-layer CTF artifacts from recorded evidence.
when_to_use:
- The challenge provides captures, traces, firmware, modulation clues, or hardware interaction notes.
when_not_to_use:
- No capture, hardware details, or reproducible measurement exists.
inputs:
- Raw captures, sample rate, modulation hints, firmware, wiring notes, or decoded packets.
outputs:
- Capture inventory, decoding steps, recovered data, and replayable analysis command.
dependencies:
- `skills/ctf-triage/SKILL.md`
- GNU Radio, URH, ChipWhisperer, and SigMF references only.
reference_digest:
- `docs/reference-digests/hardware-rf-side-channel.md`
evidence produced:
- Raw trace metadata, decoded outputs, scripts, and replay logs.
failure/blocker classes:
- Missing sample rate or capture metadata.
- Hardware dependency not available.
- Tool license or archive status unsuitable for vendoring.
future agent consumers:
- Hardware/RF solver.
- Side-channel solver.
workflow:
- Record raw capture metadata, sample rate, format, channel, modulation hints, hardware notes, firmware, and hashes.
- Preserve raw captures unchanged and write derived data under `work/`.
- Decode modulation, framing, symbols, packets, and protocol fields with command provenance.
- Use GNU Radio or URH when capture metadata and modulation hints justify SDR
  graphing or interactive signal inspection.
- Route recovered firmware, ciphertext, keys, or protocol traces to the matching category after preserving boundary evidence.
- Verify recovered data through scripts and preserved trace provenance.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `python3 work/inspect_capture.py`
- `gnuradio-config-info -v` or `urh --version` when SDR tooling is required.
- `python3 work/decode_signal.py`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
