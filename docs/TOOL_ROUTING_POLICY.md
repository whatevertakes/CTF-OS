# Tool Routing Policy

Tool routing records why an agent chose or did not choose tools during a CTF
attempt. It is an observability contract, not an enforcement layer.

## Principles

- MCP tools are optional accelerators. Do not force MCP usage when local files,
  CLI tools, debuggers, scripts, or direct protocol probes are better evidence.
- CLI and language tools may be the primary tools for a challenge. Record them
  alongside MCP tools.
- Record tools that were considered, used, skipped, or missing when that
  decision materially shaped the solve path.
- A skipped MCP tool is acceptable when the reason is explicit.
- Keep missing required dependencies separate from skipped tools. A required
  tool that is unavailable is a dependency finding, not a routing choice.
- Retrospective inferences must be marked as retrospective. Do not present a
  later reconstruction as live-session evidence.

## MCP Boundary

Configured Codex MCP servers are `angr`, `playwright`, and `radare2`.
Reverse-engineering MCP access should continue to use the `.codex/bin/`
wrappers configured in `.codex/config.toml`.

The `mcp`, `fastmcp`, `mcp-proxy`, and `mcp-reverse-proxy` commands are CLI
utilities and launch dependencies. They are checked by preflight and team
parity, but they are not expected to appear as separate `codex mcp list`
servers.

External GUI tools such as Burp Suite and Caido may be recorded when they shape
the solve path, but they are not required for team parity.

## State Schema

Challenge `state.json` files may record:

```json
"tool_routing": {
  "primary_tools_used": [],
  "considered": [],
  "used": [],
  "skipped": [],
  "missing": [],
  "decision_summary": ""
}
```

Tool entries may be strings or objects. Use objects when a reason, kind, or
retrospective marker is needed:

```json
{"tool": "angr", "kind": "mcp", "reason": "dynamic probes gave higher-value evidence"}
```

## Corpus Fields

Benchmark corpus entries may record:

- `primary_tools_used`
- `tools_considered`
- `tools_used`
- `tools_skipped`
- `missing_tools`
- `tool_routing_gap`

The evaluator accepts string entries for simple cases and object entries for
reasoned or retrospective decisions.

## Evaluation

`tools/evaluate_corpus.py` reports routing observability separately from solve
correctness:

- entries missing tool routing data
- entries with missing tools
- MCP tools considered
- MCP tools used
- MCP tools skipped with reasons
- entries where MCP is absent and no MCP decision was recorded

Tool routing gaps are caveats. They are not proof failures and are not a reason
to force MCP usage.

`tools/check_level3_tool_routing.py` is the structural gate for category helper
coverage. It verifies that installed helper CLIs such as `arjun`, `floss`,
`frida`, `zsteg`, `wafw00f`, `pwninit`, and `RsaCtfTool` appear in the
appropriate Level 3 strategy packets and category skills. This keeps CLI routing
visible without turning those tools into MCP servers.
