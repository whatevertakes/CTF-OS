# Level 2 Category Coverage

This table maps common CTF categories to local skill contracts, parity CLI
tools, optional references, configured MCPs, and current gaps. Team setup
installs the shared CLI surface; heavy target-specific tools remain deep
profile checks.

| Category | Local skill | Optional tools or references | MCP support | Gaps and notes |
|---|---|---|---|---|
| Core preflight/intake/proof | `skills/ctf-triage`, `skills/replay-runner`, `skills/proof-validation` | `tools/preflight_check.py`, `benchmarks/LEVEL2_SELFTEST.md` | None | Keep challenge state, replay evidence, redacted summaries, and proof scope current. |
| Web | `skills/ctf-web` | Browser devtools, curl/httpie-style local commands, `arjun`, `flask-unsign`, `wafw00f`, `shodan`, `sqlmap`, `ffuf`, `gobuster`; Burp/Caido as external GUI tools | Playwright MCP | Scanners are helpers, not proof. Preserve targeted requests and payload evidence. |
| Pwn | `skills/ctf-pwn` | `pwntools`, gdb, `checksec`, `ROPgadget`, `ropper`, `one_gadget`, `seccomp-tools`, `pwninit`, `patchelf`, qemu-user profiles | None | Patch loaders or use qemu only for local reproduction evidence. |
| Reverse engineering | `skills/ctf-rev` | `file`, `strings`, `objdump`, local disassemblers, `floss`, `yara`, `upx`, qemu-user profiles, Ghidra as an optional external tool, `angr` reference | radare2, angr MCP | Use `.codex/bin/` wrappers for configured local RE MCPs. |
| Crypto | `skills/ctf-crypto` | `RsaCtfTool`, Sage, z3/fplll/pari references | None | Keep math scripts challenge-local and reproducible. |
| Forensics | `skills/ctf-forensics` | `file`, `binwalk`, `foremost`, `exiftool`, `tshark`, `floss`, `stegolsb`, `zsteg`, Volatility3, file carving references | None | No default memory-symbol caches. |
| Stego | `skills/ctf-stego` | `exiftool`, `binwalk`, `steghide`, `stegolsb`, `zsteg`, image/audio metadata and carving references | None | Avoid blind bulk extraction unless evidence points there. |
| OSINT | `skills/ctf-osint` | Public search and archival references | Browser/Playwright when useful | Record sources and access dates. |
| Misc | `skills/ctf-misc` | Challenge-specific references | None | Route to a narrower skill once evidence clarifies the domain. |
| Programming/PPC | `skills/ctf-programming` | Small stdlib solvers and parsing scripts | None | Keep generated inputs and outputs under evidence when material. |
| Jail/Sandbox | `skills/ctf-jail` | Python, shell, JS, or template sandbox references | Playwright MCP for browser sandboxes | Preserve payload attempts and rejected constraints. |
| Cloud | `skills/ctf-cloud` | kCTF, provider docs, Kubernetes Goat references, `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo` | Playwright MCP for consoles only when local/owned | Do not touch real third-party infrastructure. |
| Container/Kubernetes | `skills/ctf-container` | Docker, kCTF, Kubernetes Goat references, `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo` | None | Local or owned lab targets only. |
| Blockchain/Web3 | `skills/ctf-web3` | Foundry tools (`forge`, `cast`, `anvil`, `chisel`), `solc`, `slither`, Echidna references | None | Avoid vendoring AGPL tooling; record chain state and tx hashes. |
| AI/ML security | `skills/ctf-ai-ml` | garak, Damn Vulnerable LLM Agent references | Playwright MCP for web agents | Never store API secrets in challenge files. |
| Mobile | `skills/ctf-mobile` | `jadx`, `apktool`, `frida`, `frida-ps` references | None | Add device/emulator-specific tooling only for a concrete APK/IPA. |
| Malware | `skills/ctf-malware` | Ghidra, Volatility3, sandboxing references | radare2, angr MCP | Static-first unless a safe local sandbox is established. |
| Hardware/RF | `skills/ctf-hardware-rf` | ChipWhisperer, SigMF, URH references | None | Hardware captures and sample rates must be documented. |
| Side-channel | `skills/ctf-side-channel` | ChipWhisperer and timing-analysis references | None | Preserve raw traces and analysis scripts. |

## Coverage Rule

Category skills are starting points. The challenge directory remains the source of truth, and every meaningful claim should point to a file, command, replay log, trace, packet capture, transaction, or other reproducible artifact.

Run `python3 tools/check_level3_tool_routing.py` after changing category
skills, Level 3 strategies, or parity CLI lists. The check fails when installed
helper CLIs are no longer surfaced in the expected category strategy and skill
text.
