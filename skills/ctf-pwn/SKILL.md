purpose: Work native exploitation challenges from binary properties to a replayable exploit or proof command.
when_to_use:
- The challenge centers on memory corruption, shellcode, ROP, sandbox escape, or native service exploitation.
- A web, reverse, or malware chain produces a native crash or exploit primitive.
when_not_to_use:
- The binary only needs static extraction or key recovery without exploitation.
inputs:
- Binary, libc/loader, service endpoint, crash input, source code, or trace.
outputs:
- Crash reproduction, exploit notes, final command, and replayable proof.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional pwntools or debugger references when the challenge requires them.
evidence produced:
- Binary hashes, check results, crash traces, exploit input, and replay logs.
failure/blocker classes:
- Missing matching remote environment.
- Non-deterministic exploit state.
- Unsafe target outside challenge scope.
future agent consumers:
- Pwn solver.
- Proof validator.
- Hybrid-chain solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
