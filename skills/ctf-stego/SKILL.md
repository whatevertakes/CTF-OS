purpose: Analyze hidden data in images, audio, video, documents, and other carrier files.
when_to_use:
- The challenge suggests steganography, metadata hiding, bit-plane tricks, or embedded payloads.
when_not_to_use:
- The carrier has already yielded a conventional archive, binary, or crypto artifact.
inputs:
- Carrier files, metadata, hints, dimensions, codecs, or extracted streams.
outputs:
- Extraction commands, recovered payloads, and evidence-backed interpretation.
dependencies:
- `skills/ctf-triage/SKILL.md`
evidence produced:
- File hashes, metadata output, extraction logs, recovered files, and replay entries.
failure/blocker classes:
- Lossy or modified carrier.
- Too many blind extraction paths without a hint.
- Missing original artifact.
future agent consumers:
- Stego solver.
- Forensics solver.
- Crypto solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
