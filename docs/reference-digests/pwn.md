# Pwn Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: pwn subskills for overflow, format string, heap, ROP, sandbox, and kernel patterns.
- `ref:pwntools`: local/remote exploit scripting reference.
- `ref:pwndbg`: debugger workflow reference.
- `ref:ropgadget`: gadget discovery reference.
- `ref:mitre_cwe_top25`: memory safety weakness vocabulary.

## CTF-Relevant Patterns

- First prove environment: binary, libc, loader, seccomp, argv/env, wrapper, Docker, and remote delta.
- Promote only evidenced primitives: leak, write, control-flow, heap overlap, UAF, OOB, format string, race, or sandbox escape.
- Keep exploit phases explicit: crash triage, offset/control, primitive, leak, chain, local proof, remote transcript.
- Treat one-gadget/ROP guesses as low-confidence until constraints and registers are evidenced.

## CWE/CVE Mapping

- Map stack/heap overflows to CWE-120/CWE-787-style out-of-bounds writes only when write bounds are evidenced.
- Map UAF/double-free to CWE-416/CWE-415 only after lifetime evidence exists.
- Use CVEs for known libraries only with exact version/build evidence and a reproduced behavior.

## Canonical Papers And Deep Dives

- Aleph One, "Smashing The Stack For Fun And Profit" for stack-control fundamentals.
- Phrack heap and format-string papers for historical primitive classes.
- Modern heap exploitation notes should be used as pattern references, not copied exploit scripts.

## When To Use

- Use for native binaries, emulator host bugs, shellcode, ROP, heap exploitation, seccomp bypass, and native service exploitation.

## When Not To Use

- Do not use when the artifact only needs static extraction, crypto recovery, or web request construction.
- Do not run remote live exploit replay without explicit metadata opt-in.

## Source Anchors

- `idx:pwn:upstream_ctf_skills:overview`
- `idx:pwn:pwntools:overview`
- `idx:pwn:pwndbg:overview`
- `idx:pwn:ropgadget:overview`
- `idx:pwn:angr:overview`
