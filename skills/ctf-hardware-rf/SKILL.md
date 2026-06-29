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
- ChipWhisperer, SigMF, and URH references only.
evidence produced:
- Raw trace metadata, decoded outputs, scripts, and replay logs.
failure/blocker classes:
- Missing sample rate or capture metadata.
- Hardware dependency not available.
- Tool license or archive status unsuitable for vendoring.
future agent consumers:
- Hardware/RF solver.
- Side-channel solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
