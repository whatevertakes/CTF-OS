#!/usr/bin/env bash
set -euo pipefail

find_browser() {
  local candidate

  for candidate in \
    "${PLAYWRIGHT_BROWSER_EXECUTABLE:-}" \
    "${PLAYWRIGHT_CHROMIUM_EXECUTABLE:-}"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  for candidate in "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  for candidate in \
    google-chrome \
    google-chrome-stable \
    chromium \
    chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done

  for candidate in \
    /opt/google/chrome/chrome \
    /snap/bin/chromium \
    /usr/bin/chromium \
    /usr/bin/chromium-browser; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

if [ "${1:-}" = "--print-browser" ]; then
  find_browser
  exit $?
fi

filtered_args=()
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-y" ] && [ "${2:-}" = "@playwright/mcp@0.0.75" ]; then
    shift 2
    continue
  fi
  filtered_args+=("$1")
  shift
done

browser="$(find_browser || true)"
if [ -z "$browser" ]; then
  cat >&2 <<'EOF'
playwright-mcp-codex: no Chrome/Chromium executable was found.

Install a Playwright browser with:
  npx playwright install chromium

Or set PLAYWRIGHT_BROWSER_EXECUTABLE to an executable Chrome/Chromium path.
EOF
  exit 127
fi

exec npx -y @playwright/mcp@0.0.75 --headless --isolated --executable-path "$browser" "${filtered_args[@]}"
