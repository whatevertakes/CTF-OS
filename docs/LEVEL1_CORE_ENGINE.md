# Level 1 Core Engine

Level 1 covers Codex configuration, model and reasoning settings, sandbox and
approval policy, and MCP routing for this workspace.

## Workspace Config

Workspace-local config lives at `.codex/config.toml`.

Current effective workspace settings:

- `model = "gpt-5.5"`
- `model_reasoning_effort = "xhigh"`
- `plan_mode_reasoning_effort = "xhigh"`
- `approval_policy = "never"`
- `sandbox_mode = "danger-full-access"`
- project trust for the localized workspace root is `trusted`

The shell environment policy sets `BASH_ENV` to `.codex/env.sh` and keeps CTF
workspace caches under `.cache/`.

## MCP Routing

Configured MCP servers:

- `angr`: `angr-mcp --transport stdio`
- `playwright`: `npx -y @playwright/mcp@0.0.75`
- `radare2`: `.codex/bin/r2mcp-codex.sh`

Reverse-engineering MCP tools should be reached through `.codex/bin/` wrappers
when possible, matching the workspace `AGENTS.md` contract.

`mcp`, `fastmcp`, `mcp-proxy`, and `mcp-reverse-proxy` are installed and checked
as CLI utilities. They are not separate Codex MCP server registrations.

## Config Preflight

`tools/preflight_check.py` validates the Level 1 invariants that affected the
benchmark run:

- `approval_policy = "never"`
- `sandbox_mode = "danger-full-access"`
- reasoning effort is `xhigh`
- `BASH_ENV` and `CTF_WORKSPACE_ROOT` point at this workspace
- the project is trusted
- radare2 MCP routes through `.codex/bin/r2mcp-codex.sh`
- `angr` and `playwright` MCP entries are present

## Plugin Policy

General-purpose remote plugins are disabled in the workspace-local config.
Enable them only for a specific task that requires the connector.
