# Pwn playbook

## Scope and recon

Use only challenge binaries and remotes explicitly listed in the local contest manifest. Work inside the attempt container. Record `file`, `checksec`, imports, symbols, strings, architecture, input paths, and local crash behavior. Preserve the exact binary, libc files supplied with the challenge, and command output under `/artifacts`.

## Hypotheses and tooling

Turn mitigations into testable hypotheses: ret2win or format-string disclosure, then an address leak for PIE or libc; only investigate heap behavior when the allocation path is evidenced. Use `gdb`/`gdb-multiarch`, `checksec`, `readelf`, `objdump`, `ROPgadget`/`ropper`, and `pwntools` against local copies first. For ARM/MIPS/RISC-V or kernel/initramfs inputs, branch to QEMU user or QEMU system TCG, `cpio`, and `pahole`; KVM or a physical device remains `NEEDS_REVIEW`.

## Validation and replay

Race primitive discovery, dynamic GDB exploitation, and an independent full solve. Publish leaks/overwrites immediately and use branch-private services for crash/restart loops. Save the exploit and exact remote receipt. A pattern-matching flag from the declared remote plus the exploit artifact is immediately submission-recommended; local repeatability and strict replay may follow.
