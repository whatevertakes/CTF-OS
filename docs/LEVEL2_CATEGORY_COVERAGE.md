# Level 2 Category Coverage

This table maps common CTF categories to local skill contracts, optional references, configured MCPs, and current gaps. Optional tools are not installed or loaded by default.

| Category | Local skill | Optional tools or references | MCP support | Gaps and notes |
|---|---|---|---|---|
| Core preflight/intake/proof | `skills/ctf-triage`, `skills/replay-runner`, `skills/proof-validation` | `tools/preflight_check.py`, `benchmarks/LEVEL2_SELFTEST.md` | None | Keep challenge state, replay evidence, redacted summaries, and proof scope current. |
| Web | `skills/ctf-web` | Browser devtools, curl/httpie-style local commands, public writeups as references | Playwright MCP | No default scanner. Use targeted requests and captured payloads. |
| Pwn | `skills/ctf-pwn` | `pwntools`, gdb, checksec-style helpers | None | Add tools only when a binary exploit needs them. |
| Reverse engineering | `skills/ctf-rev` | Local disassemblers, Ghidra as an optional external tool, `angr` reference | radare2, angr MCP | Use `.codex/bin/` wrappers for configured local RE MCPs. |
| Crypto | `skills/ctf-crypto` | `RsaCtfTool`, Sage references | None | Keep math scripts challenge-local and reproducible. |
| Forensics | `skills/ctf-forensics` | Volatility3, file carving references | None | No default memory-symbol caches. |
| Stego | `skills/ctf-stego` | Image/audio metadata and carving references | None | Avoid blind bulk extraction unless evidence points there. |
| OSINT | `skills/ctf-osint` | Public search and archival references | Browser/Playwright when useful | Record sources and access dates. |
| Misc | `skills/ctf-misc` | Challenge-specific references | None | Route to a narrower skill once evidence clarifies the domain. |
| Programming/PPC | `skills/ctf-programming` | Small stdlib solvers and parsing scripts | None | Keep generated inputs and outputs under evidence when material. |
| Jail/Sandbox | `skills/ctf-jail` | Python, shell, JS, or template sandbox references | Playwright MCP for browser sandboxes | Preserve payload attempts and rejected constraints. |
| Cloud | `skills/ctf-cloud` | kCTF, provider docs, Kubernetes Goat references | Playwright MCP for consoles only when local/owned | Do not touch real third-party infrastructure. |
| Container/Kubernetes | `skills/ctf-container` | kCTF, Kubernetes Goat references | None | Local or owned lab targets only. |
| Blockchain/Web3 | `skills/ctf-web3` | Foundry, Echidna references | None | Avoid vendoring AGPL tooling; record chain state and tx hashes. |
| AI/ML security | `skills/ctf-ai-ml` | garak, Damn Vulnerable LLM Agent references | Playwright MCP for web agents | Never store API secrets in challenge files. |
| Mobile | `skills/ctf-mobile` | jadx/apktool/frida references | None | Add tooling only for a concrete APK/IPA. |
| Malware | `skills/ctf-malware` | Ghidra, Volatility3, sandboxing references | radare2, angr MCP | Static-first unless a safe local sandbox is established. |
| Hardware/RF | `skills/ctf-hardware-rf` | ChipWhisperer, SigMF, URH references | None | Hardware captures and sample rates must be documented. |
| Side-channel | `skills/ctf-side-channel` | ChipWhisperer and timing-analysis references | None | Preserve raw traces and analysis scripts. |

## Coverage Rule

Category skills are starting points. The challenge directory remains the source of truth, and every meaningful claim should point to a file, command, replay log, trace, packet capture, transaction, or other reproducible artifact.
