purpose: Recover evidence from disk, memory, packet, archive, image, or log artifacts.
when_to_use:
- The primary artifact requires carving, timeline work, metadata analysis, memory analysis, or packet reconstruction.
- Extracted material may feed crypto, web, or malware analysis.
when_not_to_use:
- The artifact is already a clean binary, source tree, or mathematical problem.
inputs:
- Images, pcaps, memory dumps, archives, logs, metadata, or extracted files.
outputs:
- Artifact inventory, hashes, extraction commands, recovered files, and next-step routing.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional Volatility3, carving, tshark, floss, stegolsb, zsteg, yara, and upx
  references when required by the artifact type.
reference_digest:
- `docs/reference-digests/forensics.md`
evidence produced:
- Source hashes, extraction logs, recovered paths, and replayable commands.
failure/blocker classes:
- Corrupt or incomplete artifact.
- Missing symbols or profiles.
- Large generated cache not suitable for default workspace load.
future agent consumers:
- Forensics solver.
- Crypto solver.
- Malware solver.
- Hybrid-chain solver.
workflow:
- Put original images, pcaps, memory dumps, logs, archives, and documents in `dist/`.
- Hash and classify every artifact before carving, extraction, or conversion.
- Record timestamps, timezone assumptions, packet counts, filesystem details, archive nesting, and tool versions.
- Use tshark for pcap inventories and stream extraction; save filters and
  reassembled output paths.
- Use Volatility3/vol only for memory artifacts with compatible symbols or
  profiles; record plugin names and assumptions.
- Use zsteg or stegolsb only when carrier properties point to bit-plane or LSB
  extraction, and preserve recovered payload hashes.
- Use floss, yara, and upx when recovered binaries or suspicious scripts need
  static triage before routing to rev or malware.
- Preserve extracted files under `work/` with source offsets, commands, and hashes.
- Split artifact inventory, timeline, carving, memory/network, and crypto bridge work instead of mixing evidence types.
- Route recovered binaries, keys, ciphertext, scripts, or web traces to the matching category only after preserving boundary evidence.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `tshark -r <pcap> -q -z io,phs` for packet captures.
- `vol -f <memory> windows.info` or another scoped Volatility3 plugin for memory dumps.
- `zsteg <carrier>` or `stegolsb steglsb -r -i <carrier> -o work/recovered.bin` when LSB evidence exists.
- `floss <sample>`, `yara -r <rules> <sample>`, or `upx -t <sample>` for recovered suspicious binaries.
- `python3 tools/replay_runner.py <challenge-dir>` after a replay path exists.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
