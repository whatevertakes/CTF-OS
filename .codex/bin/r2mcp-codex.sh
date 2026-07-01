#!/usr/bin/env bash
set -euo pipefail

candidate_bins=()

if [ -n "${R2MCP_BIN:-}" ]; then
  candidate_bins+=("$R2MCP_BIN")
fi

if command -v r2mcp >/dev/null 2>&1; then
  candidate_bins+=("$(command -v r2mcp)")
fi

candidate_bins+=(
  "$HOME/.local/bin/r2mcp"
  "$HOME/.local/share/radare2/prefix/bin/r2mcp"
  "/usr/local/bin/r2mcp"
  "/usr/bin/r2mcp"
)

for libdir in \
  "$HOME/.local/lib" \
  "$HOME/.local/share/radare2/prefix/lib" \
  "/usr/local/lib"; do
  if [ -d "$libdir" ]; then
    export LD_LIBRARY_PATH="$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
done

for bin in "${candidate_bins[@]}"; do
  if [ -x "$bin" ]; then
    exec "$bin" "$@"
  fi
done

cat >&2 <<'EOF'
r2mcp-codex: r2mcp was not found.

Install radare2 MCP or set R2MCP_BIN to the r2mcp executable path.
This only affects radare2 MCP usage; normal r2 CLI use can still work.
EOF
exit 127
