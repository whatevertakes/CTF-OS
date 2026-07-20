#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ALL_PROFILES=(base pwn web rev crypto forensic misc osint ai cloud)
PROFILES=("$@")
if (( ${#PROFILES[@]} == 0 )); then PROFILES=("${ALL_PROFILES[@]}"); fi

[[ "$(uname -s)" == "Linux" ]] || {
  echo "Unsupported host OS: sandbox images are supported on Ubuntu Linux x86_64 only." >&2
  exit 65
}
if [[ ! -r /etc/os-release ]] || ! ( . /etc/os-release; [[ "${ID:-}" == "ubuntu" ]] ); then
  echo "Unsupported Linux distribution: sandbox images are supported on Ubuntu Linux x86_64 only." >&2
  exit 65
fi
if [[ "$(uname -r)" == *[Mm]icrosoft* || -n "${WSL_INTEROP:-}" ]]; then
  echo "Unsupported host environment: sandbox image builds require native Ubuntu Linux x86_64." >&2
  exit 65
fi
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) echo "Unsupported host architecture: sandbox images require Ubuntu Linux x86_64." >&2; exit 65 ;;
esac

contains_profile() {
  local wanted="$1" candidate
  for candidate in "${ALL_PROFILES[@]}"; do [[ "$candidate" == "$wanted" ]] && return 0; done
  return 1
}
for profile in "${PROFILES[@]}"; do
  contains_profile "$profile" || { echo "Unknown profile: $profile" >&2; echo "Supported: ${ALL_PROFILES[*]}" >&2; exit 64; }
done

command -v docker >/dev/null || { echo "Docker CLI not found. Install Docker before building sandbox images." >&2; exit 69; }

# Public base/tool downloads and even daemon discovery must not inherit Docker
# Desktop or personal registry credentials.
if [[ -z "${DOCKER_CONFIG:-}" ]]; then
  BUILD_DOCKER_CONFIG="$(mktemp -d "${TMPDIR:-/tmp}/ctf-os-docker-config.XXXXXX")"
  trap 'rm -rf -- "$BUILD_DOCKER_CONFIG"' EXIT
  printf '%s\n' '{"auths":{}}' >"$BUILD_DOCKER_CONFIG/config.json"
  export DOCKER_CONFIG="$BUILD_DOCKER_CONFIG"
  echo "Using an isolated Docker configuration for public image pulls."
fi

if ! daemon="$(docker info --format '{{.ServerVersion}}' 2>&1)"; then
  if [[ "$daemon" == *"permission denied"* || "$daemon" == *"Permission denied"* ]]; then
    echo "Docker socket permission denied for the current user: $daemon" >&2
  elif [[ "$daemon" == *"Cannot connect"* || "$daemon" == *"connection refused"* ]]; then
    echo "Docker daemon is stopped or unreachable: $daemon" >&2
  else
    echo "Docker daemon response error: $daemon" >&2
  fi
  exit 69
fi

if ! compose="$(docker compose version --short 2>&1)"; then
  echo "Docker Compose v2 plugin is unavailable: $compose" >&2
  exit 69
fi
docker run --help >/dev/null 2>&1 || { echo "docker run is unavailable for the current daemon/CLI." >&2; exit 69; }

free_kib="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
minimum_kib=$((20 * 1024 * 1024))
if [[ ! "$free_kib" =~ ^[0-9]+$ ]] || (( free_kib < minimum_kib )); then
  echo "Insufficient disk space: the full toolchain build requires at least 20 GiB free (found $((free_kib / 1024 / 1024)) GiB)." >&2
  exit 70
fi
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
if [[ -n "$docker_root" && -d "$docker_root" ]]; then
  docker_free_kib="$(df -Pk "$docker_root" | awk 'NR==2 {print $4}')"
  if [[ ! "$docker_free_kib" =~ ^[0-9]+$ ]] || (( docker_free_kib < minimum_kib )); then
    echo "Insufficient Docker data-root space: at least 20 GiB free is required." >&2
    exit 70
  fi
fi

export DOCKER_BUILDKIT=1
declare -a SUCCEEDED=() FAILED=() DETAILS=()
overall_start="$(date +%s)"

for profile in "${PROFILES[@]}"; do
  tag="ctf-os-sandbox:${profile}"
  started="$(date +%s)"
  echo "[$profile] BUILD start -> $tag"
  if docker build \
      --progress=plain \
      --build-arg "CTF_OS_PROFILE=${profile}" \
      --file "$ROOT/sandbox/Dockerfile.sandbox" \
      --tag "$tag" \
      "$ROOT"; then
    elapsed=$(( $(date +%s) - started ))
    metadata="$(docker image inspect "$tag" --format '{{.Id}}|{{.Size}}' 2>/dev/null || true)"
    image_id="${metadata%%|*}"; size_bytes="${metadata#*|}"
    [[ "$metadata" == *"|"* ]] || { image_id="unknown"; size_bytes="0"; }
    if [[ "$size_bytes" =~ ^[0-9]+$ ]]; then size_human="$(numfmt --to=iec-i --suffix=B "$size_bytes")"; else size_human="unknown"; fi
    echo "[$profile] PASS id=$image_id size=$size_human time=${elapsed}s"
    SUCCEEDED+=("$profile")
    DETAILS+=("$profile|PASS|$image_id|$size_human|${elapsed}s")
  else
    elapsed=$(( $(date +%s) - started ))
    echo "[$profile] FAIL time=${elapsed}s" >&2
    FAILED+=("$profile")
    DETAILS+=("$profile|FAIL|-|-|${elapsed}s")
  fi
done

echo
echo "CTF-OS sandbox build summary (Docker $daemon; Compose $compose; Ubuntu Linux x86_64)"
printf '%-10s %-6s %-20s %-12s %s\n' PROFILE STATUS IMAGE_ID SIZE TIME
for detail in "${DETAILS[@]}"; do
  IFS='|' read -r profile status image_id size elapsed <<<"$detail"
  printf '%-10s %-6s %-20s %-12s %s\n' "$profile" "$status" "${image_id:0:20}" "$size" "$elapsed"
done
echo "Total: $(( $(date +%s) - overall_start ))s; success=${#SUCCEEDED[@]}; failed=${#FAILED[@]}"

if (( ${#FAILED[@]} )); then
  echo "Failed profiles: ${FAILED[*]}" >&2
  exit 1
fi
