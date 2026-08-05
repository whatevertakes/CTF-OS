#!/usr/bin/env bash
set -euo pipefail

# One-command team setup: from a fresh clone to a pinned, doctor-clean checkout.
#
# This script never builds ctf-os-image/Dockerfile. Independent builds diverge
# because the base tag, every apt block and 22 pip lines are unpinned, so each
# host would pin a different image ID and receipts stop being comparable. The
# image is acquired from the operator instead: an already-loaded tag, a saved
# tarball, or a registry reference.

usage() {
  cat >&2 <<'EOF'
사용법: scripts/team-setup.sh [옵션]

새로 클론한 CTF-OS를 실행 가능한 상태까지 한 번에 만듭니다.
  의존성 확인 → uv sync → CLI 설치 → 이미지 확보 → init → 등급 설정
  → pin-image → doctor

이미지 확보 (셋 중 하나. 아무것도 안 주면 이미 로드된 ctf-os:core를 씁니다)
  --tar <경로>       docker save 한 tarball을 로드합니다 (.tar 또는 .tar.gz)
  --from <참조>      레지스트리에서 pull 합니다 (이 팀의 기본 경로는 --tar 입니다)
                     예: registry.lan:5000/ctf-os@sha256:<digest>
  --skip-image       이미지 단계를 건너뜁니다

검증
  --expect <이미지ID>  확보한 이미지가 이 exact local image ID인지 확인합니다
                       (환경변수 CTFOS_TEAM_IMAGE_ID 로도 지정 가능)
  --tar-sha256 <해시>  --tar 를 로드하기 전에 아카이브 해시를 검사합니다.
                       tarball 옆에 <tarball>.sha256 이 있으면 자동으로 씁니다.
                       12 GB 전송이 깨졌는지를 docker load 전에 잡습니다

호스트 등급 ([resources] 자동 설정)
  --tier S|M|L|XS    등급을 직접 지정합니다
  --tier auto        CPU/RAM에서 자동 판정합니다 (기본값)
  --tier none        engine.toml 을 건드리지 않습니다

  -h, --help         이 도움말
EOF
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "${repo_root}"

image_tar=""
image_ref=""
skip_image=0
tier_arg="auto"
expect_id="${CTFOS_TEAM_IMAGE_ID:-}"
tar_sha=""

while (($#)); do
  case "$1" in
    --tar) image_tar="${2:?--tar 뒤에 경로가 필요합니다}"; shift 2 ;;
    --from) image_ref="${2:?--from 뒤에 레지스트리 참조가 필요합니다}"; shift 2 ;;
    --expect) expect_id="${2:?--expect 뒤에 image ID가 필요합니다}"; shift 2 ;;
    --tar-sha256) tar_sha="${2:?--tar-sha256 뒤에 해시가 필요합니다}"; shift 2 ;;
    --tier) tier_arg="${2:?--tier 뒤에 S|M|L|XS|auto|none 이 필요합니다}"; shift 2 ;;
    --skip-image) skip_image=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; usage; exit 2 ;;
  esac
done

step()  { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok()    { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
warn()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
die()   { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; exit 1; }

# ctfos lands in ~/.local/bin via `uv tool install`, which may not be on PATH
# in this shell. Fall back to `uv run` so the script completes either way.
ctfos() {
  if command -v ctfos >/dev/null 2>&1; then
    command ctfos "$@"
  else
    uv run ctfos "$@"
  fi
}

# ── 1. 사전 요구 ────────────────────────────────────────────────────────────
step "1/7  사전 요구 확인"

# The host python3 only runs this script's small helpers. The project needs
# 3.13, but uv provisions that interpreter into .venv itself - Ubuntu 24.04
# ships 3.12 and that is fine. The real gate is the venv check in step 2.
command -v python3 >/dev/null || die "python3 이 없습니다"
ok "python3 $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])') (호스트 헬퍼용)"

command -v uv >/dev/null || die "uv 가 없습니다  →  curl -LsSf https://astral.sh/uv/install.sh | sh"
ok "uv $(uv --version | awk '{print $2}')"

command -v docker >/dev/null || die "docker 가 없습니다"
docker version >/dev/null 2>&1 || die "Docker 데몬이 응답하지 않습니다"
ok "docker daemon"

# doctor treats a non-zero `codex --version` as a warning, which fails the
# final gate below. Login is not needed yet - only the binary.
if codex --version >/dev/null 2>&1; then
  ok "codex CLI"
else
  warn "codex CLI 없음 → doctor 가 warning 을 냅니다. 문제 풀기 전에 설치하세요"
fi

disk_free_gib=$(df -Pk "${HOME}" | awk 'NR==2 {printf "%d", $4/1024/1024}')
if ((disk_free_gib >= 60)); then
  ok "여유 디스크 ${disk_free_gib} GiB"
else
  warn "여유 디스크 ${disk_free_gib} GiB — 60 GiB 권장 (이미지 11.8 GiB + 문제 작업공간)"
fi

# ── 2. Python 환경과 CLI ────────────────────────────────────────────────────
step "2/7  Python 환경과 ctfos 설치"

uv sync --frozen >/dev/null || die "uv sync --frozen 실패"
ok "uv sync --frozen (uv.lock 변경 없음)"

# This is the real 3.13 gate. uv downloads the interpreter when the host lacks
# it, so a 3.12 host python3 above is not a problem.
if [[ -x .venv/bin/python ]]; then
  venv_py=$(.venv/bin/python -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
  .venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else 1)' \
    || die "프로젝트 인터프리터가 ${venv_py} 입니다. 3.13 이상이 필요합니다"
  ok "프로젝트 인터프리터 ${venv_py}"
else
  warn ".venv/bin/python 이 없습니다 — uv sync 결과를 확인하세요"
fi

uv tool install --editable . >/dev/null 2>&1 || die "uv tool install 실패"
if command -v ctfos >/dev/null 2>&1; then
  ok "ctfos on PATH"
else
  warn "ctfos 가 PATH 에 없습니다 → PATH 에 ~/.local/bin 을 추가하세요 (이번 실행은 uv run 으로 진행)"
fi

# ── 3. 이미지 확보 ──────────────────────────────────────────────────────────
step "3/7  ctf-os:core 이미지"

current_id() { docker image inspect --format '{{.Id}}' ctf-os:core 2>/dev/null || true; }

if ((skip_image)); then
  ok "--skip-image"
elif [[ -n "${image_tar}" ]]; then
  [[ -r "${image_tar}" ]] || die "tarball 을 읽을 수 없습니다: ${image_tar}"

  # Catch a broken 12 GB transfer before spending 10 minutes in docker load.
  # Accepts a bare hash, a "sha256:" prefix, or a sha256sum-format sidecar.
  if [[ -z "${tar_sha}" && -r "${image_tar}.sha256" ]]; then
    tar_sha=$(awk '{print $1; exit}' "${image_tar}.sha256")
    echo "     사이드카 사용: ${image_tar}.sha256"
  fi
  if [[ -n "${tar_sha}" ]]; then
    tar_sha="${tar_sha#sha256:}"
    echo "     아카이브 해시 검사 중 (12 GB 기준 30~60초)…"
    got_sha=$(sha256sum -- "${image_tar}" | cut -d' ' -f1)
    if [[ "${got_sha}" == "${tar_sha}" ]]; then
      ok "아카이브 해시 일치"
    else
      die "아카이브 해시 불일치 — 전송이 깨졌습니다. 다시 받으세요.
       기대: ${tar_sha}
       실제: ${got_sha}"
    fi
  else
    warn "아카이브 해시 미검사 (--tar-sha256 또는 ${image_tar##*/}.sha256 사이드카를 쓰세요)"
  fi

  echo "     로드 중 (새 호스트에서 5~15분 걸립니다)…"
  case "${image_tar}" in
    *.gz) gunzip -c -- "${image_tar}" | docker load ;;
    *)    docker load -i "${image_tar}" ;;
  esac
  ok "docker load 완료"
elif [[ -n "${image_ref}" ]]; then
  echo "     pull 중: ${image_ref}"
  docker pull "${image_ref}" || die "docker pull 실패: ${image_ref}"
  docker tag "${image_ref}" ctf-os:core
  ok "pull 후 ctf-os:core 로 태그"
fi

loaded_id="$(current_id)"
if [[ -z "${loaded_id}" ]]; then
  die "ctf-os:core 가 로컬에 없습니다. 운영자 이미지를 --tar 또는 --from 으로 지정하세요.
       Dockerfile 을 직접 빌드하지 마십시오 — 호스트마다 다른 image ID 와 도구 버전이 나옵니다."
fi
ok "ctf-os:core = ${loaded_id}"

if [[ -n "${expect_id}" ]]; then
  if [[ "${loaded_id}" == "${expect_id}" ]]; then
    ok "운영자 image ID 와 일치"
  else
    die "image ID 불일치
       기대: ${expect_id}
       실제: ${loaded_id}
       다시 빌드하지 말고 운영자 이미지를 다시 받으세요."
  fi
fi

# ── 4. 설정 생성 ────────────────────────────────────────────────────────────
step "4/7  engine.toml"

if [[ -f .ctfos/engine.toml ]]; then
  ok ".ctfos/engine.toml 이미 존재 (덮어쓰지 않음)"
else
  ctfos init >/dev/null || die "ctfos init 실패"
  ok "ctfos init"
fi

# ── 5. 호스트 등급 ──────────────────────────────────────────────────────────
step "5/7  호스트 등급과 [resources]"

# doctor never reconciles [resources] against the host and never warns on a
# CPU/RAM shortfall, so an 8 GiB box reports ok:true and then stalls in the
# lease FIFO until lease_wait_timeout_s. `doctor --calibrate` only ever lowers
# (it is a min() against the current config), so it cannot size up an S host.
# The tier table is applied here instead.
host_cpu=$(nproc)
host_ram_gib=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)

if nvidia-smi -L >/dev/null 2>&1; then
  gpu_jobs=1; gpu_note="GPU 감지됨"
else
  gpu_jobs=0; gpu_note="GPU 없음 → max_gpu_jobs=0 (기본값 1 은 Docker 실행 전에 실패합니다)"
fi

if [[ "${tier_arg}" == "auto" ]]; then
  # Thresholds are below the tier table's nominal RAM because MemTotal reports
  # less than the sticker value, especially under WSL2. The reference host that
  # ran the full acceptance matrix at --jobs 2 reports 12 core / 27 GiB, so M
  # must not require 28.
  if   ((host_ram_gib >= 56 && host_cpu >= 16)); then tier=S
  elif ((host_ram_gib >= 26 && host_cpu >= 12)); then tier=M
  elif ((host_ram_gib >= 14 && host_cpu >= 8));  then tier=L
  else tier=XS
  fi
else
  tier="${tier_arg}"
fi

case "${tier}" in
  S)    tier_cpu=12; tier_mem=40; tier_jobs="--jobs 2" ;;
  M)    tier_cpu=8;  tier_mem=18; tier_jobs="--jobs 2" ;;
  L)    tier_cpu=4;  tier_mem=8;  tier_jobs="--jobs 1" ;;
  XS)   tier_cpu=2;  tier_mem=4;  tier_jobs="미지원" ;;
  none) tier_cpu=""; tier_jobs="" ;;
  *)    die "알 수 없는 등급: ${tier} (S|M|L|XS|auto|none)" ;;
esac

echo "     호스트: ${host_cpu} 코어 / ${host_ram_gib} GiB RAM"
if [[ "${tier}" == "none" ]]; then
  warn "--tier none → [resources] 를 수정하지 않았습니다"
else
  python3 - "${tier_cpu}" "${tier_mem}" "${gpu_jobs}" <<'PY' || die "engine.toml 수정 실패"
import pathlib, re, sys

cpu, mem, gpu = sys.argv[1:4]
path = pathlib.Path(".ctfos/engine.toml")
text = path.read_text(encoding="utf-8")
for key, value in (
    ("tool_cpu_budget", cpu),
    ("tool_memory_gib", mem),
    ("max_gpu_jobs", gpu),
):
    pattern = rf"(?m)^{key}\s*=.*$"
    if not re.search(pattern, text):
        raise SystemExit(f"{key} not found in engine.toml")
    text = re.sub(pattern, f"{key} = {value}", text)
path.write_text(text, encoding="utf-8")
PY
  ok "등급 ${tier} 적용 → tool_cpu_budget=${tier_cpu}  tool_memory_gib=${tier_mem}  max_gpu_jobs=${gpu_jobs}"
  echo "     ${gpu_note}"
  if [[ "${tier}" == "XS" ]]; then
    warn "XS 는 heavy 프로파일(4c/8GiB)을 admit 할 수 없습니다."
    warn "  → pwn interaction, web active probe 게이트가 돌지 않습니다. 풀이 전용으로 쓰세요."
  fi
fi

# ── 6. 핀 ───────────────────────────────────────────────────────────────────
step "6/7  pin-image"
ctfos pin-image >/dev/null || die "ctfos pin-image 실패"
ok "runtime.image_digest = ${loaded_id}"

# ── 7. 진단 ─────────────────────────────────────────────────────────────────
step "7/7  doctor"
doctor_out=$(mktemp)
trap 'rm -f "${doctor_out}"' EXIT
ctfos doctor >"${doctor_out}" 2>/dev/null || true

python3 - "${doctor_out}" "${tier}" "${tier_jobs}" "${loaded_id}" <<'PY'
import json, pathlib, socket, sys

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
path, tier, tier_jobs, image_id = sys.argv[1:5]

try:
    report = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
except Exception as exc:
    print(f"  {RED}FAIL{RESET} doctor 출력이 JSON 이 아닙니다: {exc}")
    raise SystemExit(1)

ok = report.get("ok") is True
warnings = report.get("warnings") or []
caps = report.get("managed_capabilities") or {}
missing = caps.get("missing") or []
host = report.get("host") or {}

def mark(good):
    return f"  {GREEN}OK{RESET}  " if good else f"  {RED}FAIL{RESET}"

print(f"{mark(ok)} ok={report.get('ok')}")
print(f"{mark(not warnings)} warnings={len(warnings)} {warnings if warnings else ''}")
print(f"{mark(not missing)} capability 누락={len(missing)} {missing if missing else ''}")

summary = {
    "hostname": socket.gethostname(),
    "tier": tier,
    "release_matrix": tier_jobs,
    "image_id": image_id,
    "doctor_ok": ok,
    "warnings": warnings,
    "missing_capabilities": missing,
    "host": host,
}
out = pathlib.Path(".ctfos/team-setup-report.json")
out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print()
if ok and not warnings and not missing:
    print(f"{GREEN}준비 완료.{RESET}  등급 {tier} · release matrix {tier_jobs}")
    print(f"  결과 요약: {out}  ← 팀에 공유해서 서로 대조하세요")
    print("  다음: codex 로그인 → incoming/ 에 문제 넣기 → ctfos add-challenge")
    raise SystemExit(0)

print(f"{YELLOW}미완.{RESET} 위 FAIL 항목을 해결한 뒤 다시 실행하세요. 이 상태로 대회를 시작하지 마십시오.")
print(f"  결과 요약: {out}")
raise SystemExit(1)
PY
