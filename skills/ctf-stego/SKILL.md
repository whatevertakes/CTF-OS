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
reference_digest:
- `docs/reference-digests/stego.md`
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
workflow:
- Hash carrier files and record dimensions, codec, channels, frame count, palette, metadata, compression, and chunk structure.
- Avoid broad blind extraction until a hint or carrier property justifies it.
- Test metadata, appended data, archive signatures, bit planes, palette changes, frame deltas, transforms, audio channels, and text encodings with provenance.
- Store recovered payloads under `work/`, rehash them, and route conventional artifacts to forensics, crypto, rev, or misc.
- Make `replay.sh` reproduce the extraction path or verify the recovered payload.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `exiftool <carrier>` when available and justified.
- `python3 work/extract.py`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
