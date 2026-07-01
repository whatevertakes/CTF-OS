#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== 복구: main 동기화 =="
git fetch origin main
if git ls-files --error-unmatch .codex/config.toml >/dev/null 2>&1 && ! git diff --quiet -- .codex/config.toml; then
  echo "pull 전에 tracked .codex/config.toml 변경을 되돌립니다."
  git restore .codex/config.toml
fi
git pull --ff-only origin main

echo "== 복구: 로컬 설정 갱신 =="
tools/bootstrap_wsl2.sh --skip-apt --skip-python --skip-preflight

echo "== 복구: 검증용 워크스페이스 환경 로드 =="
# shellcheck disable=SC1091
. .codex/env.sh

echo "== 복구: 검증 =="
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
codex mcp list

cat <<EOF

복구 완료.

예상 성공 표시:
  summary failures=0 warnings=0
  team parity summary failures=0
  codex mcp list에 angr, playwright, radare2 표시

이 디렉터리에서 Codex를 다시 시작하세요.
  cd "$ROOT"
  . .codex/env.sh
  codex
EOF
