# Toolchain Matrix

This matrix records dependency expectations for CTF challenge triage and
benchmark evaluation. Strict preflight checks the shared team parity CLI
surface; deep category checks add heavier or target-specific tools.

| Category | Required Tools | Optional Tools |
| --- | --- | --- |
| `mcp-cli` | `mcp`, `fastmcp`, `mcp-proxy`, `mcp-reverse-proxy` | CLI utility surface only; registered MCP servers remain `angr`, `playwright`, `radare2`. |
| `pwn` | `gcc`, `gdb`, `python3`, `pwntools`, `checksec`, `ROPgadget`, `ropper`, `pwninit` | `one_gadget`, `seccomp-tools`, qemu profiles. |
| `rev` | `file`, `strings`, `r2`, `angr`, `floss` | `ghidra`, `yara`, `upx`, qemu profiles. |
| `web` | `curl`, `python3`, `node`, `playwright`, `arjun`, `flask-unsign`, `wafw00f`, `shodan` | `Burp Suite`, `Caido` as external GUI tools. |
| `crypto` | `python3`, `RsaCtfTool` | `sage`, `z3`, `fplll`, `pari-gp`. |
| `forensics` | `binwalk`, `exiftool`, `tshark`, `floss`, `stegolsb`, `zsteg` | `foremost`, `volatility3`, `yara`, `upx`. |
| `mobile` | `jadx`, `apktool`, `frida`, `frida-ps` | Device/emulator-specific tooling. |
| `firmware/hardware-rf/avr` | `avr-gcc`, `avr-objdump`, `avr-objcopy`, `avr-size` | `avrdude`, `simavr` |

`mcp-reverse-proxy` is maintained as a compatibility CLI wrapper over
`mcp-proxy`. It is not a separate Codex MCP server registration.

`RsaCtfTool` is installed in an isolated user-level venv by
`tools/bootstrap_wsl2.sh` because its upstream dependency pins can downgrade
general-purpose Python packages. `pwninit` uses the upstream release binary; the
legacy PyPI package is not Python 3 compatible.

Corpus entries may record dependency state with:

- `required_tools`: tool names required for the benchmark case.
- `missing_tools`: known missing tools at the time of evaluation.
- `dependency_status`: one of `ok`, `missing`, or `unknown`.

Tool routing observability is separate from dependency health. Use
`docs/TOOL_ROUTING_POLICY.md` for `primary_tools_used`, `tools_considered`,
`tools_used`, `tools_skipped`, and `tool_routing_gap` semantics.
