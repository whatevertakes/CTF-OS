# Reverse Engineering Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: reverse subskills for tools, anti-analysis, runtime patterns, languages, and platforms.
- `ref:angr`: symbolic execution and binary analysis reference.
- `ref:angr_examples`: bounded symbolic examples.
- `ref:radare2`: disassembly and analysis reference.
- `ref:ghidra`: decompiler reference.

## CTF-Relevant Patterns

- Identify input format, output format, success predicate, anti-debug behavior, and high-value functions before broad symbolic execution.
- Extract constants, tables, encodings, and constraints with commands and offsets.
- Use dynamic traces to bound lengths, branches, syscalls, and side effects.
- Patch only to observe one named check, then verify final candidates against unpatched semantics.

## CWE/CVE Mapping

- CVEs matter only for known packed protectors, runtimes, libraries, or interpreter bugs with version evidence.
- If recovered behavior is memory corruption, route to pwn with proof of primitive.
- If recovered behavior is math or protocol cryptography, route to crypto with extracted parameters.

## Canonical Papers And Deep Dives

- Angr examples and symbolic execution literature for path constraint modeling.
- Decompilation and dynamic instrumentation references for preserving original semantics.

## When To Use

- Use for native binaries, bytecode, firmware, packers, anti-debugging, checkers, and extracted algorithms.

## When Not To Use

- Do not use symbolic execution before concrete bounds exist.
- Do not treat patched-binary success as final proof.

## Source Anchors

- `idx:rev:upstream_ctf_skills:overview`
- `idx:rev:angr:overview`
- `idx:rev:angr_examples:overview`
- `idx:rev:radare2:overview`
- `idx:rev:ghidra:overview`
- `idx:rev:jadx:overview`
- `idx:rev:frida:overview`
