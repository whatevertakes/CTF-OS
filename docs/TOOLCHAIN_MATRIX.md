# Toolchain Matrix

This matrix records lightweight dependency expectations for CTF challenge
triage and benchmark evaluation. Global preflight remains small; category
specific checks are opt-in.

| Category | Required Tools | Optional Tools |
| --- | --- | --- |
| `pwn` | `gcc`, `gdb`, `python3`, `pwntools` | |
| `rev` | `file`, `strings`, `r2`, `ghidra` | |
| `web` | `curl`, `python3`, `node`, `playwright` | |
| `crypto` | `python3` | `sage` |
| `forensics` | `binwalk`, `exiftool` | `foremost` |
| `firmware/hardware-rf/avr` | `avr-gcc`, `avr-objdump`, `avr-objcopy`, `avr-size` | `avrdude`, `simavr` |

Corpus entries may record dependency state with:

- `required_tools`: tool names required for the benchmark case.
- `missing_tools`: known missing tools at the time of evaluation.
- `dependency_status`: one of `ok`, `missing`, or `unknown`.

Tool routing observability is separate from dependency health. Use
`docs/TOOL_ROUTING_POLICY.md` for `primary_tools_used`, `tools_considered`,
`tools_used`, `tools_skipped`, and `tool_routing_gap` semantics.
