#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TEAM_BRANCHES=(
  shyunseok1029
  holymo-ly
  lee
  jiwoongchoi-norun
)

MODE="quick"
FETCH=1
RUN_REGRESSION=0
RUN_DEEP=0

usage() {
  cat <<'EOF'
Usage: tools/admin_status.sh [--quick|--full] [--deep] [--no-fetch] [--regression]

Owner/admin status check for the shared CTF workspace.

Default:
  --quick       Run the checks needed before telling teammates to sync.

Options:
  --full        Also check reference materialization and corpus health.
  --deep        Run category deep tool profiles. This can take a few minutes.
  --regression  Run tools/regression_check.py.
  --no-fetch    Do not contact origin.
EOF
}

run() {
  echo
  echo "== $* =="
  "$@"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quick) MODE="quick" ;;
    --full) MODE="full" ;;
    --deep) RUN_DEEP=1 ;;
    --regression) RUN_REGRESSION=1 ;;
    --no-fetch) FETCH=0 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "FAIL unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

echo "== workspace =="
echo "$ROOT"
echo "branch=$(git branch --show-current 2>/dev/null || true)"
echo "commit=$(git rev-parse --short HEAD 2>/dev/null || true)"

if [ "$FETCH" -eq 1 ] && git remote get-url origin >/dev/null 2>&1; then
  run git fetch --all --prune
fi

echo
echo "== team branches =="
for branch in "${TEAM_BRANCHES[@]}"; do
  if git show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    ahead_behind="$(git rev-list --left-right --count "origin/main...origin/$branch" 2>/dev/null || printf 'unknown unknown')"
    printf 'PASS origin/%-18s main...branch %s\n' "$branch" "$ahead_behind"
  else
    printf 'WARN origin/%s missing\n' "$branch"
  fi
done

echo
echo "== local git changes =="
git status --short

run python3 tools/localize_codex_config.py --root "$ROOT"

# shellcheck disable=SC1091
. .codex/env.sh

run python3 tools/preflight_check.py --strict-optional
run python3 tools/check_team_parity.py
run python3 tools/check_level3_tool_routing.py
run python3 tools/reference_digest_check.py
run codex mcp list
run .codex/bin/playwright-mcp-codex.sh --print-browser

if [ "$MODE" = "full" ]; then
  run python3 tools/check_references.py
  run python3 tools/evaluate_corpus.py
fi

if [ "$RUN_REGRESSION" -eq 1 ]; then
  run python3 tools/regression_check.py
fi

if [ "$RUN_DEEP" -eq 1 ]; then
  echo
  echo "== deep category profiles =="
  for category in crypto forensics malware mobile pwn rev misc programming stego web web3 cloud container ai-ml hardware-rf side-channel; do
    echo "-- $category --"
    python3 tools/preflight_check.py --deep --category "$category" | grep -E '^(PASS deep|WARN deep|FAIL deep|summary)'
  done
fi

cat <<EOF

== admin next commands ==
If this report is clean, send teammates one of these:

  git fetch origin
  git switch <their-branch>
  git merge origin/main
  tools/team_member_setup.sh --branch <their-branch> --deep --skip-garak

For a teammate repair:

  tools/repair_team_setup.sh

Before merging a data PR:

  python3 tools/validate_data_submission.py --base origin/main
  python3 tools/evaluate_corpus.py
EOF
