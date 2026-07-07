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
DEEP_CHECK=1
BOOTSTRAP_MINIMAL=0
SKIP_APT=0
SKIP_PYTHON=0
SKIP_MCP=0
SKIP_ADVANCED=0
SKIP_GARAK=0
STRICT_EXTERNAL=0
TARGET_BRANCH=""

usage() {
  cat <<'EOF'
사용법: tools/team_member_setup.sh [--branch <github-user>] [--deep] [--minimal] [--skip-apt] [--skip-python] [--skip-mcp] [--skip-advanced] [--skip-garak] [--strict-external]

팀원용 우승 기준 1회 설정/검증 스크립트입니다.
  - 자기 팀 브랜치인지 확인하거나 --branch 값으로 전환
  - 현재 clone 경로에 맞는 .codex/config.toml 생성
  - tools/bootstrap_wsl2.sh 실행
  - strict preflight와 team parity 검증
  - codex mcp list에서 angr/playwright/radare2 연결 확인
  - CTF 카테고리별 고급 도구 설치와 deep profile 검증

팀 브랜치:
  shyunseok1029
  holymo-ly
  lee
  jiwoongchoi-norun

--deep은 호환용 옵션입니다. 팀 설정은 기본적으로 deep 설치/검증을 수행합니다.
--skip-advanced는 고급 도구 설치를 건너뛰고 검증만 수행합니다.
--skip-garak은 설치 중 대형 AI/ML 도구 garak만 건너뜁니다.
--strict-external은 GUI/라이선스/클라우드 등 manual external 도구 누락도 실패로 처리합니다.
EOF
}

is_team_branch() {
  local branch="$1"
  local candidate
  for candidate in "${TEAM_BRANCHES[@]}"; do
    if [ "$branch" = "$candidate" ]; then
      return 0
    fi
  done
  return 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --branch)
      if [ "$#" -lt 2 ]; then
        echo "FAIL --branch에는 브랜치 이름이 필요합니다." >&2
        exit 2
      fi
      TARGET_BRANCH="$2"
      shift
      ;;
    --deep) DEEP_CHECK=1 ;;
    --minimal) BOOTSTRAP_MINIMAL=1 ;;
    --skip-apt) SKIP_APT=1 ;;
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-mcp) SKIP_MCP=1 ;;
    --skip-advanced) SKIP_ADVANCED=1 ;;
    --skip-garak) SKIP_GARAK=1 ;;
    --strict-external) STRICT_EXTERNAL=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "FAIL 알 수 없는 인자: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ -n "$TARGET_BRANCH" ] && ! is_team_branch "$TARGET_BRANCH"; then
  echo "FAIL 허용된 팀 브랜치가 아닙니다: $TARGET_BRANCH" >&2
  exit 2
fi

echo "== 팀 브랜치 확인 =="
git fetch origin

if [ -n "$TARGET_BRANCH" ]; then
  current_branch="$(git branch --show-current || true)"
  if [ "$current_branch" != "$TARGET_BRANCH" ]; then
    if git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
      git switch "$TARGET_BRANCH"
    else
      git switch --track "origin/$TARGET_BRANCH"
    fi
  fi
fi

current_branch="$(git branch --show-current || true)"
if ! is_team_branch "$current_branch"; then
  cat >&2 <<EOF
FAIL 현재 브랜치는 팀원 작업 브랜치가 아닙니다: ${current_branch:-detached}

다음 중 자기 브랜치로 전환한 뒤 다시 실행하세요.
  git switch --track origin/shyunseok1029
  git switch --track origin/holymo-ly
  git switch --track origin/lee
  git switch --track origin/jiwoongchoi-norun

또는:
  tools/team_member_setup.sh --branch <github-user>
EOF
  exit 1
fi
echo "PASS branch $current_branch"

echo "== 로컬 Codex 설정 생성 =="
python3 tools/localize_codex_config.py --root "$ROOT"

bootstrap_args=()
if [ "$BOOTSTRAP_MINIMAL" -eq 1 ]; then
  bootstrap_args+=(--minimal)
fi
if [ "$SKIP_APT" -eq 1 ]; then
  bootstrap_args+=(--skip-apt)
fi
if [ "$SKIP_PYTHON" -eq 1 ]; then
  bootstrap_args+=(--skip-python)
fi

echo "== 부트스트랩 실행 =="
tools/bootstrap_wsl2.sh "${bootstrap_args[@]}"

echo "== 워크스페이스 환경 로드 =="
# shellcheck disable=SC1091
. .codex/env.sh
if [ "$CTF_WORKSPACE_ROOT" != "$ROOT" ]; then
  echo "FAIL CTF_WORKSPACE_ROOT mismatch: $CTF_WORKSPACE_ROOT != $ROOT" >&2
  exit 1
fi
echo "PASS CTF_WORKSPACE_ROOT=$CTF_WORKSPACE_ROOT"

echo "== strict preflight =="
python3 tools/preflight_check.py --strict-optional

echo "== team parity =="
python3 tools/check_team_parity.py

if [ "$SKIP_MCP" -eq 0 ]; then
  echo "== Codex MCP 연결 확인 =="
  if ! command -v codex >/dev/null 2>&1; then
    echo "FAIL codex CLI를 찾을 수 없습니다. Codex 설치/로그인 후 다시 실행하세요." >&2
    exit 1
  fi
  mcp_output="$(codex mcp list)"
  printf '%s\n' "$mcp_output"
  for required_mcp in angr playwright radare2; do
    if ! printf '%s\n' "$mcp_output" | grep -Eq "^${required_mcp}[[:space:]]"; then
      echo "FAIL Codex MCP 누락: $required_mcp" >&2
      exit 1
    fi
  done
  echo "PASS Codex MCP angr/playwright/radare2"
fi

if [ "$DEEP_CHECK" -eq 1 ]; then
  if [ "$SKIP_ADVANCED" -eq 0 ]; then
    echo "== 고급 CTF 도구 설치 =="
    advanced_args=()
    if [ "$SKIP_APT" -eq 1 ]; then
      advanced_args+=(--skip-apt)
    fi
    if [ "$SKIP_GARAK" -eq 1 ]; then
      advanced_args+=(--skip-garak)
    fi
    tools/install_advanced_ctf_tools.sh "${advanced_args[@]}"
  fi

  # shellcheck disable=SC1091
  . .codex/env.sh
  echo "== 고급 CTF strict deep profile 검증 =="
  deep_managed_failures=0
  deep_external_failures=0
  deep_external_missing=0
  external_policy="report"
  if [ "$STRICT_EXTERNAL" -eq 1 ]; then
    external_policy="fail"
  fi
  deep_managed_report="$(mktemp)"
  deep_external_report="$(mktemp)"
  for category in crypto forensics malware mobile pwn rev misc programming stego web web3 cloud container ai-ml hardware-rf side-channel; do
    echo "CHECK deep $category"
    category_report="$(mktemp)"
    set +e
    python3 tools/preflight_check.py --strict-deep --external-policy "$external_policy" --category "$category" >"$category_report"
    deep_status=$?
    set -e
    if grep -Eq '^FAIL deep' "$category_report"; then
      deep_managed_failures=$((deep_managed_failures + 1))
      {
        echo "-- $category --"
        grep -E '^FAIL deep' "$category_report" || true
        printf 'managed_failure_lines=%s\n' "$(grep -Ec '^FAIL deep' "$category_report" || true)"
      } >>"$deep_managed_report"
    fi
    if grep -Eq '^EXTERNAL deep' "$category_report"; then
      deep_external_failures=$((deep_external_failures + 1))
      category_external_missing="$(awk '
        /^summary / {
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^external_missing=/) {
              split($i, parts, "=")
              missing += parts[2]
            }
            if ($i ~ /^external_failed=/) {
              split($i, parts, "=")
              failed += parts[2]
            }
          }
        }
        END { print missing + failed + 0 }
      ' "$category_report")"
      deep_external_missing=$((deep_external_missing + category_external_missing))
      {
        echo "-- $category --"
        grep -E '^EXTERNAL deep' "$category_report" || true
        printf 'external_missing_failed=%s\n' "$category_external_missing"
      } >>"$deep_external_report"
    fi
    if [ "$deep_status" -ne 0 ] && ! grep -Eq '^(FAIL deep|EXTERNAL deep)' "$category_report"; then
      deep_managed_failures=$((deep_managed_failures + 1))
      {
        echo "-- $category --"
        grep -E '^FAIL ' "$category_report" || true
        grep -E '^summary ' "$category_report" || true
      } >>"$deep_managed_report"
    fi
    rm -f "$category_report"
  done
  echo "-- hardware-rf avr --"
  python3 tools/preflight_check.py --category hardware-rf --tag avr | grep -E '^(PASS command avr|PASS dependency avr|FAIL dependency_missing|summary)'
  if [ "$deep_external_missing" -ne 0 ]; then
    echo "== strict deep external manual report =="
    cat "$deep_external_report"
    echo "INFO strict deep external manual missing: $deep_external_missing"
  fi
  if [ "$deep_managed_failures" -ne 0 ] || { [ "$STRICT_EXTERNAL" -eq 1 ] && [ "$deep_external_failures" -ne 0 ]; }; then
    if [ "$deep_managed_failures" -ne 0 ]; then
      echo "== strict deep managed failures =="
      cat "$deep_managed_report"
      echo "FAIL strict deep managed categories failed: $deep_managed_failures" >&2
    fi
    if [ "$STRICT_EXTERNAL" -eq 1 ] && [ "$deep_external_failures" -ne 0 ]; then
      echo "FAIL strict deep external categories failed: $deep_external_failures" >&2
    fi
    rm -f "$deep_managed_report" "$deep_external_report"
    exit 1
  fi
  rm -f "$deep_managed_report" "$deep_external_report"
fi

cat <<EOF

팀원 워크스페이스 설정 완료.
브랜치: $current_branch
워크스페이스: $ROOT

이후 작업:
  python3 tools/benchmark_runner.py run challenges/<event>/<category>/<challenge>
  python3 tools/evaluate_corpus.py
  git push origin HEAD:$current_branch
EOF
