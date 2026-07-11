# Reverse engineering playbook

## Scope and recon

Analyze only provided binaries, bytecode, mobile packages, or source inside the attempt container. Identify format, architecture, libraries, embedded data, packers, strings, and execution inputs with `file`, `strings`, hashes, and controlled local runs. Copy untouched originals and log each transformation.

## Hypotheses and tooling

Map the input-to-check path before attempting a solve. Use `radare2`, Ghidra where available, `ltrace`, `strace`, debugger breakpoints, decompilation, and small Python helpers. Consider encoding, XOR, comparison logic, anti-debug checks, packed sections, symbolic constraints, or checksum routines only when static or dynamic evidence supports them.

## Validation and replay

Validate a candidate by tracing the exact comparison branch or by replaying the program with a captured input. Keep scripts, patched copies clearly labeled, function addresses for the original hash, and concise notes about assumptions. Do not treat an unverified decoded string as a result.
