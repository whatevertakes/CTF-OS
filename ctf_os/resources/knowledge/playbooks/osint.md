# OSINT playbook

## Scope and first branches

Use only public targets and artifacts named by the challenge. Begin with provenance: domain/DNS and certificate metadata, archived-page history, image/document metadata and OCR, video frames, map clues, or public Git history. Do not import personal cookies or browser profiles, bypass login, enumerate accounts at scale, or correlate unrelated people.

## Evidence-led pivots

Use `whois`, `dig`, `httpx`, `waybackurls`, and headless Chromium for public web history; `exiftool`, ImageMagick, OpenCV, and `tesseract` for visual evidence; `yt-dlp` and `ffmpeg` only for an authorized public media target. Preserve URLs, timestamps, hashes, and the precise clue connecting each pivot. Keep request volume small and within the remote allowlist.

## Validation

Corroborate identity or location clues with at least two independent public observations. Save redacted captures and commands, distinguish observation from inference, and stop at login walls or private systems rather than expanding access.
