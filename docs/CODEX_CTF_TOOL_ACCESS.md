# Codex CTF Tool Access

This document describes the CTF tool surface that this workspace expects Codex
to use. It is a contract for setup, routing, and verification; it is not a
machine-specific audit log.

Use it with `docs/TOOLCHAIN_MATRIX.md`, `docs/TOOL_ROUTING_POLICY.md`,
`capabilities/registry.yaml`, and the matching `skills/*/SKILL.md` file.

## Workspace Tool Layers

| Layer | Contract |
| --- | --- |
| Workspace root | Run from the repository root that contains `AGENTS.md`. `.codex/env.sh` should set `CTF_WORKSPACE_ROOT` and prepend `.codex/bin`, `.venv/bin`, and `~/.local/bin`. |
| Skills | CTF category skills live under `skills/ctf-*/SKILL.md`; bootstrap creates local `.agents/skills/*` symlinks for Codex skill discovery. |
| Core CLI | `tools/preflight_check.py` validates required files, Python modules, optional CLI tools, MCP wrapper configuration, references, and skill contracts. |
| Parity CLI | `tools/check_team_parity.py` validates the shared CTF command surface, Docker runtime, proxy helpers, Playwright wrapper, reverse MCP helpers, Python packages, and Level 3 routing. |
| MCP wrappers | Configured Codex MCP servers are `angr`, `playwright`, and `radare2`; use `.codex/bin/` wrappers where configured. |
| Web proxy helpers | `.codex/bin/ctf-proxy-start` and `.codex/bin/ctf-proxy-check` provide optional Caido bridge support for web CTF traffic inspection. |
| Reference layer | `references.yaml`, `references.lock.json`, `docs/reference-digests/`, and `docs/reference-index/` define the curated reference surface; `.cache/references/` is local cache only. |

## Codex Usage Rules

- Read the matching CTF category skill before acting on a category-specific
  challenge.
- Use `.codex/bin/r2mcp-codex.sh` for radare2 MCP and
  `.codex/bin/playwright-mcp-codex.sh` for Playwright MCP.
- Treat `mcp`, `fastmcp`, `mcp-proxy`, and `mcp-reverse-proxy` as CLI support
  utilities, not separate registered Codex MCP servers.
- For reverse MCP, load the target binary before running analysis calls.
- For Playwright MCP, use the configured wrapper; it should choose an available
  Chromium or Chrome executable and use isolated browser state.
- Keep challenge evidence under `challenges/<event>/<category>/<challenge>/`
  and use `tools/replay_runner.py` plus `tools/proof_validate.py` before
  treating a solve as stable.

## Category Tool Surface

| Category | Expected tools |
| --- | --- |
| Core/triage | `intake_challenge.py`, `replay_runner.py`, `proof_validate.py`, templates, evidence layout |
| Web | Playwright MCP, `curl`, Python HTTP clients, `arjun`, `flask-unsign`, `wafw00f`, `shodan`, `sqlmap`, `ffuf`, `gobuster`, `tplmap`, `searchsploit`, optional Caido/Burp helpers |
| Pwn | `gcc`, `gdb`, `pwntools`, `checksec`, `ROPgadget`, `ropper`, `one_gadget`, `seccomp-tools`, `pwninit`, `patchelf`, qemu profiles |
| Rev | `file`, `strings`, `objdump`, `r2`, radare2 MCP, angr MCP, `floss`, Ghidra wrappers, `yara`, `upx`, qemu profiles |
| Crypto | `RsaCtfTool`, Sage, `z3`, `fplll`, PARI/GP, Python verifier workflow |
| Forensics | `binwalk`, `exiftool`, `tshark`, Volatility3, Sleuth Kit, `floss`, `stegolsb`, `zsteg`, `yara`, `upx` |
| Stego | `exiftool`, `binwalk`, `steghide`, `stegseek`, `zsteg`, `stegolsb` |
| Mobile | `jadx`, `apktool`, `adb`, `objection`, `frida`, `frida-ps` |
| Malware | `floss`, `yara`, `upx`, Volatility3, `tshark`, radare2 MCP, angr MCP |
| Web3 | Foundry `forge`/`cast`/`anvil`, `chisel`, `solc`, `slither`, `halmos` |
| Cloud/container | Docker, `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo` |
| AI/ML | Python prompt/model harnesses, garak |
| Hardware/RF | AVR toolchain, GNU Radio, URH, Python capture scripts |
| Side-channel | GNU Radio and Python trace/timing/power/cache analysis scripts |
| Programming | Python deterministic parsers/solvers, z3 |

## Verification Commands

Run these after changing setup, tools, skills, MCP config, or routing policy:

```bash
python3 tools/localize_codex_config.py --root "$(pwd)"
. .codex/env.sh
python3 tools/preflight_check.py
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
python3 tools/check_level3_tool_routing.py
codex mcp list
.codex/bin/playwright-mcp-codex.sh --print-browser
```

Run a category deep check when a challenge needs advanced tooling:

```bash
python3 tools/preflight_check.py --deep --category <category>
```

Categories with dedicated deep profiles include `pwn`, `rev`, `crypto`,
`forensics`, `malware`, `mobile`, `programming`, `stego`, `web`, `web3`,
`cloud`, `container`, `ai-ml`, `hardware-rf`, `side-channel`, and `misc`.
`osint`, `jail`, and `hybrid` rely on skill workflows and handoff routing
instead of a standalone deep CLI profile.
