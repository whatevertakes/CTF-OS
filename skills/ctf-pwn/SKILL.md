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
- Optional pwntools, debugger, ROPgadget, ropper, one_gadget,
  seccomp-tools, pwninit, pwndbg-gdb, patchelf, qemu-user, and Docker
  references when the challenge requires them.
reference_digest:
- `docs/reference-digests/pwn.md`
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
workflow:
- Put original binaries, libc, loader, docker-compose, wrapper scripts, and source in `dist/`.
- Start with `file`, `sha256sum`, `checksec`, local run behavior, and Docker/service reproduction.
- Record architecture, mitigations, libc/loader identity, seccomp, argv/env, and network wrapper assumptions in `notes.md`.
- Use ROPgadget or ropper only after a control-flow or ROP/JOP need is
  evidenced; save the exact gadget query and selected gadget offsets.
- Use one_gadget only when a matching libc is known or recovered; record libc
  hash, constraints, and why the constraints are satisfiable.
- Use seccomp-tools when seccomp is detected or suspected; preserve the dumped
  policy before building sandbox escape or syscall chains.
- Use pwninit only to align a provided binary, libc, and loader; do not let it
  replace recorded environment facts.
- Use pwndbg-gdb when interactive heap, stack, register, or exploit-state
  inspection is needed; preserve reproduced commands and crash facts.
- Use patchelf only to reproduce a provided loader/libc environment locally;
  record original interpreter/RPATH before changing a copy.
- Use qemu-user only when architecture mismatch blocks local reproduction, and
  keep the qemu command in replay evidence.
- Minimize crashes before exploit development; save crash input, signal, offset, controlled bytes, and register/heap context.
- Promote only evidenced primitives such as leak, write, control-flow, UAF, OOB, format string, sandbox escape, or race.
- Write exploit drafts under `work/`, and make `replay.sh` run the narrowest local proof command before attempting remote proof.
- Capture remote attempts as transcripts with timing, retry count, leak values, and exact failure reason; do not rerun remote live exploit replay without explicit opt-in.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `checksec --file <binary>`
- `ROPgadget --binary <binary>` or `ropper --file <binary>` after a ROP need is evidenced.
- `seccomp-tools dump <binary>` when seccomp is detected or suspected.
- `pwninit --bin <binary> --libc <libc> --ld <loader>` when matching runtime files are provided.
- `pwndbg-gdb <binary>` when interactive exploit debugging is justified.
- `patchelf --print-interpreter <binary>` before patching a local copy.
- `qemu-<arch> <binary>` when cross-architecture local execution is justified and safe.
- `python3 work/exploit_*.py LOCAL=1`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
