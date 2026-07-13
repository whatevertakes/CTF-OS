# Forensic playbook

## Scope and recon

Operate only on challenge artifacts and make a hash before inspection. Identify file type, size, metadata, archive structure, timestamps, and embedded content using read-only copies. Keep an evidence log that names the original hash and every extracted derivative.

## Hypotheses and tooling

Branch by evidence family: Volatility for a memory image; Sleuth Kit (`mmls`, `fls`, `icat`), TestDisk/PhotoRec, or `foremost` for disks and deleted files; `tshark`/Scapy for PCAP; `binwalk` for firmware; `exiftool`, `zsteg`, `stegseek`, ImageMagick, and `tesseract` for metadata, stego, and OCR; `ffmpeg`/`sox` for media. Check container structure before carving and treat every hidden stream as a hypothesis until its offset and decoding are repeatable.

## Validation and replay

Validate extraction by confirming offsets, hashes, parser output, and the relation to the original artifact. Store commands, tool versions, extracted files, and a short replay script under `/artifacts`. Do not modify originals or infer a flag from an unexplained fragment.
