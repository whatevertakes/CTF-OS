# Forensic playbook

## Scope and recon

Operate only on challenge artifacts and make a hash before inspection. Identify file type, size, metadata, archive structure, timestamps, and embedded content using read-only copies. Keep an evidence log that names the original hash and every extracted derivative.

## Hypotheses and tooling

Use `exiftool`, `strings`, `binwalk`, `foremost`, `tshark`, `zsteg`, `steghide`, and format-specific parsers according to evidence. Check simple container, archive, image, audio, and packet structures before expensive carving. Treat metadata or a hidden stream as a hypothesis until its origin and decoding are repeatable.

## Validation and replay

Validate extraction by confirming offsets, hashes, parser output, and the relation to the original artifact. Store commands, tool versions, extracted files, and a short replay script under `/artifacts`. Do not modify originals or infer a flag from an unexplained fragment.
