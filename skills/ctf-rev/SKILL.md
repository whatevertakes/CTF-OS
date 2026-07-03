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
- Optional Ghidra external tooling, configured radare2/angr MCP integration,
  floss, yara, upx, qemu-user, and local debugger tooling when evidence
  requires them.
reference_digest:
- `docs/reference-digests/rev.md`
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
workflow:
- Put original binaries, bytecode, firmware, traces, and supporting files in `dist/`.
- Start with hashes, `file`, strings, imports, architecture, packer indicators, and local run behavior.
- Use floss when regular strings are sparse or obfuscated string recovery is
  plausible; save recovered strings that drive hypotheses.
- Use yara and upx checks when packer, malware-like, or known-family
  indicators matter; keep rule names and unpacking commands with hashes.
- Use qemu-user only for cross-architecture local behavior that can be safely
  reproduced from the challenge artifact.
- Identify input format, success predicate, output format, anti-debug checks, high-value functions, and extracted constants.
- Use dynamic tracing to bound real lengths, branch conditions, syscalls, and side effects before broad symbolic execution.
- Patch only to observe or bypass one named check; preserve original bytes and verify final candidates against unpatched semantics.
- Save solver, emulator, deobfuscator, and patch scripts under `work/`; save verification output under `evidence/`.
- Escalate to crypto when the recovered core is math, to pwn when the recovered core is memory corruption, and to malware when safe handling matters.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `strings -a <binary> | head`
- `floss <binary>` when obfuscated strings are suspected.
- `upx -t <binary>` or `yara -r <rules> <binary>` when packer or rule evidence is relevant.
- `qemu-<arch> <binary>` when cross-architecture local execution is justified and safe.
- `r2 -A <binary>` when radare2 is justified by the artifact.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
