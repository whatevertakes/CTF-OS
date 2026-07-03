# Level 0 Infrastructure

Level 0 covers the local OS, shell, git, Docker, language runtimes, MCP tool
binaries, and cache or environment paths used by this CTF workspace.

## Current Contract

- Active workspace root: the repository root containing `AGENTS.md`
- Shell environment entrypoint: `.codex/env.sh`
- Workspace cache root: `.cache/`
- Python workspace virtualenv: `.venv/`
- Local command wrappers: `.codex/bin/`
- Challenge work root: `challenges/`
- Infrastructure preflight: `python3 tools/preflight_check.py`

## Web CTF Tooling

The workspace exposes these command wrappers through `.codex/bin/`:

- `searchsploit` -> `.cache/tools/exploitdb/searchsploit`
- `tplmap` -> `.cache/tools/tplmap/tplmap.py` using `.venv/bin/python`

Core web CTF Python packages are installed in `.venv`, not system Python:

- `requests`
- `httpx`
- `aiohttp`
- `beautifulsoup4`
- `lxml`
- `flask`
- `jinja2`
- `pwntools`
- `sqlmap`
- `defusedxml`
- `PyYAML`

Reverse-engineering and pwn proof packages used by the self-test challenges are
also installed in `.venv`:

- `capstone`
- `pefile`
- `pwntools`
- `unicorn`

## Container and Native Tooling

Docker is part of the Level 0 strict profile because pwn, web, and hybrid
challenges often require the provided jail or service topology:

- Docker client: `/usr/bin/docker`
- Docker daemon: reachable through `docker info`
- Observed Docker version during the 2026-06-30 recheck: `29.5.3`

The strict profile also tracks the CTF tools that are already present in this
workspace or user path:

- pwn/native: `checksec`, `ROPgadget`, `one_gadget`, `ropper`, `seccomp-tools`
- reverse/browser/MCP support: `r2`, `angr-mcp`, `node`, `npm`, `npx`
- mobile/forensics/math: `jadx`, `apktool`, `tshark`, `sage`

These tools are not loaded into every solve. They are availability checks so a
future agent can choose a narrow tool when the challenge evidence justifies it.

During the 2026-06-30 recheck, `mikuprotect` replay initially failed because
`pefile` was missing from `.venv`. Installing `pefile==2024.8.26` restored the
local replay proof.

## Preflight Check

Run this before benchmark replay, after environment changes, or after restoring
the workspace on a new machine:

```bash
python3 tools/preflight_check.py
```

The check verifies required root paths, `.codex/bin/` wrappers, core commands,
the `.venv` Python modules needed by the self-test challenges, Docker daemon
reachability, installed CTF tools, Level 1 Codex config invariants, and the
implemented Level 2-4 benchmark/script/document entry points. It treats
optional tools as warnings unless `--strict-optional` is used.

Use the strict profile before closing Level 0 or starting a benchmark suite:

```bash
python3 tools/preflight_check.py --strict-optional
```

## System Package State

`apt update` and `apt upgrade -y` were run on 2026-06-29. Ubuntu kept back
`libgl1-amber-dri` and `libglapi-mesa`. An explicit upgrade attempt for only
those packages failed because `libglapi-amber` breaks `libglapi-mesa`; this is
a graphics stack conflict and is not required for the current web CTF workflow.

`python3-venv` and `pipx` are installed. The Ubuntu repositories available on
this machine do not provide an `exploitdb` or `searchsploit` package, so the
Exploit-DB Git source is cached under `.cache/tools/exploitdb`.

## Path Policy

`.codex/env.sh` prepends:

1. `.codex/bin`
2. `.venv/bin`
3. `$HOME/.local/bin`

Windows `/mnt/c/*` PATH entries are removed unless `CODEX_KEEP_WINDOWS_PATH=1`
is set.
