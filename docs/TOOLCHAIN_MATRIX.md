# Toolchain Matrix

This matrix records dependency expectations for CTF challenge triage and
benchmark evaluation. Strict preflight checks the shared team parity CLI
surface; deep category checks add heavier or target-specific tools.

| Category | Required Tools | Optional Tools |
| --- | --- | --- |
| `mcp-cli` | `mcp`, `fastmcp`, `mcp-proxy`, `mcp-reverse-proxy` | CLI utility surface only; registered MCP servers remain `angr`, `playwright`, `radare2`. |
| `pwn` | `gcc`, `gdb`, `python3`, `pwntools`, `checksec`, `ROPgadget`, `ropper`, `pwninit` | `pwndbg-gdb`, `one_gadget`, `seccomp-tools`, `patchelf`, qemu profiles. |
| `rev` | `file`, `strings`, `objdump`, `r2`, `angr`, `floss` | `ghidra`, `ghidra-analyzeHeadless`, `yara`, `upx`, qemu profiles. |
| `web` | `curl`, `python3`, `node`, `playwright`, `arjun`, `flask-unsign`, `wafw00f`, `shodan`, `sqlmap` | `ffuf`, `gobuster`, `Burp Suite`, `Caido` as external GUI tools. |
| `crypto` | `python3`, `RsaCtfTool` | `sage`, `z3`, `fplll`, `pari-gp`. |
| `forensics` | `binwalk`, `exiftool`, `tshark`, `floss`, `stegolsb`, `zsteg` | `foremost`, `sleuthkit` (`fls`, `mmls`), `volatility3`, `yara`, `upx`. |
| `stego` | `file`, `exiftool`, `zsteg`, `stegolsb` | `binwalk`, `steghide`, `stegseek`, custom extractors. |
| `mobile` | `jadx`, `apktool`, `frida`, `frida-ps` | `adb`, `objection`, device/emulator-specific tooling. |
| `web3` | `python3`, `forge`, `cast`, `anvil`, `slither` | `chisel`, `solc`, `halmos`, `echidna` when specifically required. |
| `cloud` | `python3`, `jq`, local config parsers | `kubectl`, provider CLIs, `trivy`, `syft`, `grype`, `crane`, `skopeo` inside owned scope. |
| `container/k8s` | `docker`, `tar`, `jq` | `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo`, namespace/capability helpers. |
| `firmware/hardware-rf/avr` | `avr-gcc`, `avr-objdump`, `avr-objcopy`, `avr-size` | `avrdude`, `simavr` |
| `ai-ml` | `python3`, challenge-local scripts | `garak` for scoped model behavior probes. |
| `hardware-rf/side-channel` | `python3`, raw captures/traces | `gnuradio`, `urh`, ChipWhisperer when specifically required. |

`mcp-reverse-proxy` is maintained as a compatibility CLI wrapper over
`mcp-proxy`. It is not a separate Codex MCP server registration.

`RsaCtfTool` is installed in an isolated user-level venv by
`tools/bootstrap_wsl2.sh` because its upstream dependency pins can downgrade
general-purpose Python packages. `pwninit` uses the upstream release binary; the
legacy PyPI package is not Python 3 compatible.

Large advanced tools are installed only on demand with
`tools/install_advanced_ctf_tools.sh`. They are intentionally excluded from the
default team bootstrap because Ghidra, garak/PyTorch, and GNU Radio add several
GB of local dependencies.

Corpus entries may record dependency state with:

- `required_tools`: tool names required for the benchmark case.
- `missing_tools`: known missing tools at the time of evaluation.
- `dependency_status`: one of `ok`, `missing`, or `unknown`.

Tool routing observability is separate from dependency health. Use
`docs/TOOL_ROUTING_POLICY.md` for `primary_tools_used`, `tools_considered`,
`tools_used`, `tools_skipped`, and `tool_routing_gap` semantics.
