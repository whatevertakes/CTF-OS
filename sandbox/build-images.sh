#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ALL_PROFILES=(base pwn web rev crypto forensic misc osint ai cloud)
PROFILES=("$@")
if (( ${#PROFILES[@]} == 0 )); then PROFILES=("${ALL_PROFILES[@]}"); fi

[[ "$(uname -s)" == "Linux" ]] || {
  echo "Unsupported host OS: sandbox images require Ubuntu or Kali Linux x86_64." >&2
  exit 65
}
if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported Linux distribution: cannot read /etc/os-release (Ubuntu or Kali Linux x86_64 required)." >&2
  exit 65
fi
source /etc/os-release
case "${ID:-}" in
  ubuntu|kali) ;;
  *) echo "Unsupported Linux distribution: sandbox images require Ubuntu or Kali Linux x86_64." >&2; exit 65 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) echo "Unsupported host architecture: sandbox images require Ubuntu or Kali Linux x86_64." >&2; exit 65 ;;
esac
HOST_DISTRIBUTION="${ID^^}"
if [[ "$(uname -r)" == *[Mm]icrosoft* || -n "${WSL_INTEROP:-}" ]]; then
  HOST_RUNTIME="WSL2_${HOST_DISTRIBUTION}_X86_64"
else
  HOST_RUNTIME="NATIVE_${HOST_DISTRIBUTION}_X86_64"
fi

repository_fstype="$(findmnt -T "$ROOT" -n -o FSTYPE 2>/dev/null || true)"
if [[ "$ROOT" =~ ^/mnt/[[:alpha:]](/|$) || "$repository_fstype" == "drvfs" ]]; then
  echo "WARNING: repository is on a Windows drvfs mount ($ROOT)." >&2
  echo "For Docker build context, forensic extraction, receipt ledger, and atomic many-file operations, use the WSL2 Linux filesystem (for example /home/<user>/CTF-OS)." >&2
fi

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
  # DOCKER_CONFIG also controls the per-user CLI plugin directory. Preserve
  # an installed Compose v2 binary while keeping registry credentials absent.
  USER_HOME_DIR="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)"
  for compose_candidate in \
      "${USER_HOME_DIR:-/nonexistent}/.docker/cli-plugins/docker-compose" \
      /usr/libexec/docker/cli-plugins/docker-compose \
      /usr/local/libexec/docker/cli-plugins/docker-compose \
      /usr/lib/docker/cli-plugins/docker-compose \
      /usr/local/lib/docker/cli-plugins/docker-compose; do
    [[ -x "$compose_candidate" ]] || continue
    candidate_version="$("$compose_candidate" version --short 2>/dev/null || true)"
    candidate_major="${candidate_version#v}"; candidate_major="${candidate_major%%.*}"
    if [[ "$candidate_major" == "2" ]]; then
      mkdir -p "$BUILD_DOCKER_CONFIG/cli-plugins"
      ln -s "$(readlink -f "$compose_candidate")" "$BUILD_DOCKER_CONFIG/cli-plugins/docker-compose"
      break
    fi
  done
  export DOCKER_CONFIG="$BUILD_DOCKER_CONFIG"
  echo "Using an isolated Docker configuration for public image pulls."
fi

if ! server_info="$(docker info --format '{{.ServerVersion}}|{{.OSType}}|{{.Architecture}}|{{.DockerRootDir}}' 2>&1)"; then
  if [[ "$server_info" == *"permission denied"* || "$server_info" == *"Permission denied"* ]]; then
    echo "Docker socket permission denied for the current user: $server_info" >&2
  elif [[ "$server_info" == *"Cannot connect"* || "$server_info" == *"connection refused"* ]]; then
    echo "Docker daemon is stopped or unreachable: $server_info" >&2
  else
    echo "Docker daemon response error: $server_info" >&2
  fi
  exit 69
fi
IFS='|' read -r daemon docker_os docker_arch docker_root <<<"$server_info"
if [[ -z "$daemon" || "$docker_os" != "linux" || ! "$docker_arch" =~ ^(x86_64|amd64)$ ]]; then
  echo "Unsupported Docker server platform: ServerVersion=${daemon:-unknown} OSType=${docker_os:-unknown} Architecture=${docker_arch:-unknown}; Linux/amd64 is required." >&2
  exit 69
fi

if ! compose="$(docker compose version --short 2>&1)"; then
  echo "Docker Compose v2 plugin is unavailable: $compose" >&2
  exit 69
fi
compose_major="${compose#v}"; compose_major="${compose_major%%.*}"
if [[ "$compose_major" != "2" ]]; then
  echo "Docker Compose v2 plugin is required (found: ${compose:-unknown})." >&2
  exit 69
fi
docker build --help >/dev/null 2>&1 || { echo "docker build is unavailable for the current daemon/CLI." >&2; exit 69; }
docker run --help >/dev/null 2>&1 || { echo "docker run is unavailable for the current daemon/CLI." >&2; exit 69; }

free_kib="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
minimum_kib=$((20 * 1024 * 1024))
if [[ ! "$free_kib" =~ ^[0-9]+$ ]] || (( free_kib < minimum_kib )); then
  echo "Insufficient disk space: the full toolchain build requires at least 20 GiB free (found $((free_kib / 1024 / 1024)) GiB)." >&2
  exit 70
fi
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
echo "CTF-OS sandbox build summary"
echo "Host runtime: $HOST_RUNTIME"
echo "Docker: ServerVersion=$daemon OSType=$docker_os Architecture=$docker_arch"
echo "Compose: $compose"
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
