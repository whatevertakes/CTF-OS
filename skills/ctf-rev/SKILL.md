purpose: Extract behavior, constants, algorithms, and constraints from binaries or bytecode.
when_to_use:
- The main work is static or dynamic reverse engineering.
- A later crypto, pwn, or malware step depends on recovered logic.
when_not_to_use:
- The artifact is already a clear exploit script, plaintext algorithm, or packet capture.
inputs:
- Binary, bytecode, firmware, packed sample, strings, traces, or decompiler output.
outputs:
- Extracted constants, pseudocode notes, control-flow findings, and solver inputs.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional Ghidra, radare2, or angr MCP integration.
evidence produced:
- Hashes, strings, disassembly notes, extracted data, and reproduction commands.
failure/blocker classes:
- Missing architecture or loader context.
- Packed/encrypted sample without unpacking evidence.
- Tool mismatch requiring a narrower MCP or local helper.
future agent consumers:
- Reverse solver.
- Crypto solver.
- Pwn solver.
- Malware solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
