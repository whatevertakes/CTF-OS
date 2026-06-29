#!/usr/bin/env bash
set -euo pipefail

R2_PREFIX="/home/choijiwng/.local/share/radare2/prefix"
R2_LIBDIR="/home/choijiwng/.local/lib"
export PATH="$R2_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$R2_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$R2_PREFIX/bin/r2mcp" "$@"
