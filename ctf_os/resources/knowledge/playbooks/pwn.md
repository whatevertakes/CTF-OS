# Pwn playbook

## Scope and recon

Use only challenge binaries and remotes explicitly listed in the local contest manifest. Work inside the attempt container. Record `file`, `checksec`, imports, symbols, strings, architecture, input paths, and local crash behavior. Preserve the exact binary, libc files supplied with the challenge, and command output under `/artifacts`.

## Hypotheses and tooling

Turn mitigations into testable hypotheses: ret2win or format-string disclosure, then an address leak for PIE or libc; only investigate heap behavior when the allocation path is evidenced. Use `gdb`/`gdb-multiarch`, `checksec`, `readelf`, `objdump`, `ROPgadget`/`ropper`, and `pwntools` against local copies first. For ARM/MIPS/RISC-V or kernel/initramfs inputs, branch to QEMU user or QEMU system TCG, `cpio`, and `pahole`; KVM or a physical device remains `NEEDS_REVIEW`.

## Validation and replay

Validate every primitive locally: demonstrate the overwrite or leak, confirm addresses from the intended build, and make one minimally scoped request to an authorized remote only after the local result is repeatable. Save the input, exploit script, protections observed, outputs, and a replay command. A crash or a plausible string is a finding, not a flag.
