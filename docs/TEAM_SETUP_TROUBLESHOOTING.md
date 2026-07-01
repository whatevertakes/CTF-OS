# Team Setup Troubleshooting

Use this page when a team member has already cloned the repo but setup or MCP
does not behave like the owner environment.

## One Command Repair

From the repo root:

```bash
cd ~/ctf_workspace
tools/repair_team_setup.sh
```

This command:

- restores local `.codex/config.toml` if a failed MCP experiment changed it
- pulls the latest `main`
- rewrites `.codex/config.toml` for the local clone path
- reruns strict setup checks
- prints `codex mcp list`

Expected success markers:

```text
summary failures=0 warnings=0
team parity summary failures=0
```

`codex mcp list` should include:

```text
angr
playwright
radare2
```

`Auth Unsupported` is normal for these local stdio MCP servers.

## Version Report

For a clean version report, do not paste long manual command blocks. Run:

```bash
cd ~/ctf_workspace
tools/version_report.sh
```

Expected final section:

```text
== final checks ==
summary failures=0 warnings=0
team parity summary failures=0
```

## Start Codex

After repair succeeds, start a new Codex session from the repo root:

```bash
cd ~/ctf_workspace
. .codex/env.sh
codex
```

Inside Codex, run:

```text
/mcp
```

Expected MCP servers:

```text
angr
playwright
radare2
```

## Common Errors

### `.codex/config.toml would be overwritten by merge`

Run:

```bash
cd ~/ctf_workspace
tools/repair_team_setup.sh
```

The repair script intentionally restores local `.codex/config.toml` before
pulling. Challenge data should not be stored in `.codex/config.toml`.

### `MCP client for angr failed to start`

Run:

```bash
cd ~/ctf_workspace
git pull origin main
tools/bootstrap_wsl2.sh --skip-apt --skip-python --skip-preflight
```

The current `main` suppresses the FastMCP startup banner for `angr-mcp`; without
that env setting, stdio handshaking can fail.

### `. .codex/env.sh` prints nothing

That is normal. The command updates the current shell environment. Confirm with:

```bash
echo "$CTF_WORKSPACE_ROOT"
which angr-mcp
```

Expected shape:

```text
/home/<user>/ctf_workspace
/home/<user>/ctf_workspace/.venv/bin/angr-mcp
```
