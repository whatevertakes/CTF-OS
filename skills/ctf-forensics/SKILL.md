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
- Optional Volatility3 or carving references when required.
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
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
