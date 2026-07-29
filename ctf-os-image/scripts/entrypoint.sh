#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: entrypoint.sh COMMAND [ARG...]

Initializes /work from the read-only /challenge directory once, records
provenance under /work/.ctf, and then execs COMMAND without reading stdin.

Environment:
  CTF_CHALLENGE_DIR  Challenge source directory (default: /challenge)
  CTF_WORK_DIR       Writable work directory (default: /work)
  CTF_UNSAFE_ALLOW_WRITABLE_CHALLENGE=1
                     Test-only override for a writable challenge source
EOF
}

if (($# == 0)); then
  usage
  exit 2
fi

challenge_dir=${CTF_CHALLENGE_DIR:-/challenge}
work_dir=${CTF_WORK_DIR:-/work}

if [[ "${challenge_dir}" != /* || "${work_dir}" != /* ]]; then
  printf 'entrypoint: challenge and work paths must be absolute\n' >&2
  exit 1
fi
challenge_dir=$(realpath -m -- "${challenge_dir}")
work_dir=$(realpath -m -- "${work_dir}")
if [[ "${challenge_dir}" == / || "${work_dir}" == / ]]; then
  printf 'entrypoint: refusing filesystem root as challenge or work path\n' >&2
  exit 1
fi
if [[
  "${challenge_dir}" == "${work_dir}" ||
  "${challenge_dir}" == "${work_dir}/"* ||
  "${work_dir}" == "${challenge_dir}/"*
]]; then
  printf 'entrypoint: challenge and work paths must not overlap\n' >&2
  exit 1
fi
if [[ -e "${work_dir}" && ! -d "${work_dir}" ]]; then
  printf 'entrypoint: work path is not a directory: %q\n' "${work_dir}" >&2
  exit 1
fi
if [[ -e "${challenge_dir}" && ! -d "${challenge_dir}" ]]; then
  printf 'entrypoint: challenge path is not a directory: %q\n' "${challenge_dir}" >&2
  exit 1
fi

unsafe_writable_override=${CTF_UNSAFE_ALLOW_WRITABLE_CHALLENGE:-0}
if [[ "${unsafe_writable_override}" != 0 && "${unsafe_writable_override}" != 1 ]]; then
  printf 'entrypoint: CTF_UNSAFE_ALLOW_WRITABLE_CHALLENGE must be 0 or 1\n' >&2
  exit 1
fi
challenge_source_present=false
challenge_mount_read_only=false
writable_override_used=false
challenge_mount_target=''
challenge_mount_options=''
if [[ -d "${challenge_dir}" ]]; then
  challenge_has_inputs=false
  if [[ -n $(
    find "${challenge_dir}" -mindepth 1 -maxdepth 1 \
      ! -name '.ctf' ! -name '.ctfos' -print -quit
  ) ]]; then
    challenge_has_inputs=true
  fi
  if ! mount_json=$(findmnt -J -T "${challenge_dir}" -o TARGET,OPTIONS); then
    printf 'entrypoint: cannot inspect challenge mount: %q\n' "${challenge_dir}" >&2
    exit 1
  fi
  challenge_mount_target=$(jq -r '.filesystems[0].target // ""' <<<"${mount_json}")
  challenge_mount_options=$(jq -r '.filesystems[0].options // ""' <<<"${mount_json}")
  canonical_mount_target=$(realpath -m -- "${challenge_mount_target}")
  challenge_is_mount=false
  [[ "${canonical_mount_target}" == "${challenge_dir}" ]] && challenge_is_mount=true
  case ",${challenge_mount_options}," in
    *,ro,*) challenge_mount_read_only=true ;;
  esac
  if [[ "${challenge_is_mount}" == true || "${challenge_has_inputs}" == true ]]; then
    challenge_source_present=true
    if [[ "${challenge_mount_read_only}" != true ]]; then
      if [[ "${unsafe_writable_override}" == 1 ]]; then
        writable_override_used=true
      else
        printf 'entrypoint: challenge source must be mounted read-only: %q\n' \
          "${challenge_dir}" >&2
        exit 1
      fi
    fi
  fi
fi

metadata_dir="${work_dir}/.ctf"
inventory_path="${metadata_dir}/challenge.sha256"
tree_path="${metadata_dir}/challenge.tree"
metadata_path="${metadata_dir}/challenge.json"

emit_challenge_inventory() {
  if [[ ! -d "${challenge_dir}" ]]; then
    return 0
  fi
  (
    cd -- "${challenge_dir}"
    find . \( -path './.ctf' -o -path './.ctfos' \) -prune \
      -o \( -type f -o -type l \) -printf '%P\0' \
      | LC_ALL=C sort -z \
      | xargs -0 -r sha256sum --
  )
}

emit_challenge_tree() {
  if [[ ! -d "${challenge_dir}" ]]; then
    return 0
  fi
  (
    cd -- "${challenge_dir}"
    while IFS= read -r -d '' relative_path; do
      mode=$(stat -c '%a' -- "${relative_path}")
      if [[ -L "${relative_path}" ]]; then
        content_digest=$(sha256sum -- "${relative_path}" | awk '{ print $1 }')
        printf 'L\0%s\0%s\0' "${mode}" "${relative_path}"
        readlink -z -- "${relative_path}"
        printf '%s\0' "${content_digest}"
      elif [[ -f "${relative_path}" ]]; then
        content_digest=$(sha256sum -- "${relative_path}" | awk '{ print $1 }')
        printf 'F\0%s\0%s\0%s\0' \
          "${mode}" "${relative_path}" "${content_digest}"
      elif [[ -d "${relative_path}" ]]; then
        printf 'D\0%s\0%s\0' "${mode}" "${relative_path}"
      fi
    done < <(
      find . -mindepth 1 \
        \( -path './.ctf' -o -path './.ctfos' \) -prune \
        -o -printf '%P\0' \
        | LC_ALL=C sort -z
    )
  )
}

load_metadata_json() {
  python3 - "${metadata_path}" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
limit = 1024 * 1024
flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
descriptor = os.open(path, flags)
try:
    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > limit:
        raise ValueError("metadata must be a regular file no larger than 1 MiB")
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(descriptor, min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit:
        raise ValueError("metadata grew beyond 1 MiB")
finally:
    os.close(descriptor)

value = json.loads(data.decode("utf-8"))
if not isinstance(value, dict):
    raise ValueError("metadata root must be an object")
json.dump(value, sys.stdout, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
PY
}

if [[ "${challenge_source_present}" == true ]]; then
  unsupported_entry=$(
    find "${challenge_dir}" \
      \( -path "${challenge_dir}/.ctf" -o -path "${challenge_dir}/.ctfos" \) \
      -prune \
      -o ! -type d ! -type f ! -type l -print -quit
  )
  if [[ -n "${unsupported_entry}" ]]; then
    printf 'entrypoint: special files are unsupported challenge inputs: %q\n' \
      "${unsupported_entry}" >&2
    exit 1
  fi

  while IFS= read -r -d '' link_path; do
    link_target=$(readlink -- "${link_path}")
    if [[ "${link_target}" == /* ]]; then
      printf 'entrypoint: absolute challenge symlink is unsupported: %q\n' \
        "${link_path}" >&2
      exit 1
    fi
    if ! resolved_target=$(realpath -e -- "${link_path}" 2>/dev/null); then
      printf 'entrypoint: broken challenge symlink is unsupported: %q\n' \
        "${link_path}" >&2
      exit 1
    fi
    if [[
      ! -f "${resolved_target}" ||
      "${resolved_target}" != "${challenge_dir}/"* ||
      "${resolved_target}" == "${challenge_dir}/.ctf" ||
      "${resolved_target}" == "${challenge_dir}/.ctf/"* ||
      "${resolved_target}" == "${challenge_dir}/.ctfos" ||
      "${resolved_target}" == "${challenge_dir}/.ctfos/"*
    ]]; then
      printf 'entrypoint: challenge symlink must target an internal regular file: %q\n' \
        "${link_path}" >&2
      exit 1
    fi
  done < <(
    find "${challenge_dir}" \
      \( -path "${challenge_dir}/.ctf" -o -path "${challenge_dir}/.ctfos" \) \
      -prune \
      -o -type l -print0
  )
fi

if [[ -L "${metadata_dir}" ]]; then
  printf 'entrypoint: refusing symlink metadata directory: %q\n' "${metadata_dir}" >&2
  exit 1
fi
mkdir -p -- "${work_dir}" "${metadata_dir}"

# A container normally has one entrypoint, but a bounded lock also makes manual
# concurrent invocations deterministic.  Close the descriptor before exec so a
# child process cannot retain the lock.
lock_fd_open=0
if command -v flock >/dev/null 2>&1; then
  exec 9<"${metadata_dir}"
  lock_fd_open=1
  if ! flock -w 30 9; then
    printf 'entrypoint: timed out waiting for initialization lock\n' >&2
    exit 1
  fi
fi

if [[ -e "${metadata_path}" || -L "${metadata_path}" ]]; then
  if ! metadata_json=$(load_metadata_json 2>/dev/null); then
    printf 'entrypoint: provenance metadata is unsafe, oversized, or invalid: %q\n' \
      "${metadata_path}" >&2
    exit 1
  fi
  source_present=${challenge_source_present}
  if ! jq -e \
    --arg challenge_dir "${challenge_dir}" \
    --arg work_dir "${work_dir}" \
    --arg inventory_path "${inventory_path}" \
    --arg tree_path "${tree_path}" \
    --argjson source_present "${source_present}" \
    --argjson mount_read_only "${challenge_mount_read_only}" \
    --argjson writable_override_used "${writable_override_used}" '
      .schema_version == 1 and
      .status == "initialized" and
      .source.path == $challenge_dir and
      .source.present == $source_present and
      .source.mount_read_only == $mount_read_only and
      .source.writable_override_used == $writable_override_used and
      .work.path == $work_dir and
      .inventory.algorithm == "sha256" and
      .inventory.path == $inventory_path and
      (.inventory.digest | type == "string") and
      .tree.format == "ctf-tree-v1-nul" and
      .tree.path == $tree_path and
      (.tree.digest | type == "string")
    ' <<<"${metadata_json}" >/dev/null 2>&1; then
    printf 'entrypoint: provenance does not match this challenge/work context: %q\n' \
      "${metadata_path}" >&2
    exit 1
  fi
  if [[ ! -f "${inventory_path}" || -L "${inventory_path}" ]]; then
    printf 'entrypoint: provenance inventory is missing or unsafe: %q\n' \
      "${inventory_path}" >&2
    exit 1
  fi
  if [[ ! -f "${tree_path}" || -L "${tree_path}" ]]; then
    printf 'entrypoint: canonical tree inventory is missing or unsafe: %q\n' \
      "${tree_path}" >&2
    exit 1
  fi
  recorded_digest=$(jq -r '.inventory.digest' <<<"${metadata_json}")
  actual_digest=$(sha256sum -- "${inventory_path}" | awk '{ print $1 }')
  if [[ "${recorded_digest}" != "${actual_digest}" ]]; then
    printf 'entrypoint: provenance inventory digest mismatch: %q\n' \
      "${inventory_path}" >&2
    exit 1
  fi
  recorded_tree_digest=$(jq -r '.tree.digest' <<<"${metadata_json}")
  actual_tree_digest=$(sha256sum -- "${tree_path}" | awk '{ print $1 }')
  if [[ "${recorded_tree_digest}" != "${actual_tree_digest}" ]]; then
    printf 'entrypoint: canonical tree inventory digest mismatch: %q\n' \
      "${tree_path}" >&2
    exit 1
  fi
  current_digest=$(emit_challenge_inventory | sha256sum | awk '{ print $1 }')
  if [[ "${current_digest}" != "${actual_digest}" ]]; then
    printf 'entrypoint: challenge differs from initialized provenance; use a fresh /work\n' >&2
    exit 1
  fi
  current_tree_digest=$(emit_challenge_tree | sha256sum | awk '{ print $1 }')
  if [[ "${current_tree_digest}" != "${actual_tree_digest}" ]]; then
    printf 'entrypoint: challenge tree differs from initialized provenance; use a fresh /work\n' >&2
    exit 1
  fi
else
  unexpected_work_entry=$(
    find "${work_dir}" -mindepth 1 -maxdepth 1 ! -name '.ctf' -print -quit
  )
  if [[ -n "${unexpected_work_entry}" ]]; then
    printf 'entrypoint: uninitialized work directory is not empty: %q\n' \
      "${unexpected_work_entry}" >&2
    printf 'entrypoint: use a fresh /work to preserve exact challenge provenance\n' >&2
    exit 1
  fi

  inventory_tmp=$(mktemp "${metadata_dir}/.challenge.sha256.XXXXXX")
  tree_tmp=$(mktemp "${metadata_dir}/.challenge.tree.XXXXXX")
  metadata_tmp=$(mktemp "${metadata_dir}/.challenge.json.XXXXXX")
  stage_dir=$(mktemp -d "${metadata_dir}/.challenge-stage.XXXXXX")

  cleanup() {
    if [[ -n ${stage_dir:-} && ${stage_dir} == "${metadata_dir}/.challenge-stage."* ]]; then
      rm -rf -- "${stage_dir}"
    fi
    if [[ -n ${inventory_tmp:-} && ${inventory_tmp} == "${metadata_dir}/.challenge.sha256."* ]]; then
      rm -f -- "${inventory_tmp}"
    fi
    if [[ -n ${tree_tmp:-} && ${tree_tmp} == "${metadata_dir}/.challenge.tree."* ]]; then
      rm -f -- "${tree_tmp}"
    fi
    if [[ -n ${metadata_tmp:-} && ${metadata_tmp} == "${metadata_dir}/.challenge.json."* ]]; then
      rm -f -- "${metadata_tmp}"
    fi
  }
  trap cleanup EXIT

  source_present=${challenge_source_present}
  file_count=0
  total_bytes=0

  if [[ "${source_present}" == true ]]; then
    # Hash regular files in bytewise path order.  Top-level .ctf (container
    # metadata) and .ctfos (host-engine state) are never copied or hashed.
    emit_challenge_inventory >"${inventory_tmp}"
    emit_challenge_tree >"${tree_tmp}"

    read -r file_count total_bytes < <(
      find "${challenge_dir}" \
        \( -path "${challenge_dir}/.ctf" -o -path "${challenge_dir}/.ctfos" \) \
        -prune \
        -o \( -type f -o -type l \) -printf '%s\n' \
        | awk '
            { count += 1; total += $1 }
            END { printf "%.0f %.0f\n", count + 0, total + 0 }
          '
    )

    # Stage first so a failed source read never leaves a half-copied top-level
    # entry.  /work was verified empty above, so this is an exact source copy.
    while IFS= read -r -d '' source_entry; do
      cp -a -- "${source_entry}" "${stage_dir}/"
    done < <(
      find "${challenge_dir}" -mindepth 1 -maxdepth 1 \
        ! -name '.ctf' ! -name '.ctfos' -print0 \
        | LC_ALL=C sort -z
    )
    while IFS= read -r -d '' staged_entry; do
      cp -a -- "${staged_entry}" "${work_dir}/"
    done < <(
      find "${stage_dir}" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z
    )
  else
    : >"${inventory_tmp}"
    : >"${tree_tmp}"
  fi

  inventory_digest=$(sha256sum -- "${inventory_tmp}" | awk '{ print $1 }')
  tree_digest=$(sha256sum -- "${tree_tmp}" | awk '{ print $1 }')
  initialized_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

  jq -n \
    --arg challenge_dir "${challenge_dir}" \
    --arg work_dir "${work_dir}" \
    --arg inventory_path "${inventory_path}" \
    --arg inventory_digest "${inventory_digest}" \
    --arg tree_path "${tree_path}" \
    --arg tree_digest "${tree_digest}" \
    --arg mount_target "${challenge_mount_target}" \
    --arg mount_options "${challenge_mount_options}" \
    --arg initialized_at "${initialized_at}" \
    --argjson source_present "${source_present}" \
    --argjson mount_read_only "${challenge_mount_read_only}" \
    --argjson writable_override_used "${writable_override_used}" \
    --argjson file_count "${file_count}" \
    --argjson total_bytes "${total_bytes}" \
    '{
      schema_version: 1,
      status: "initialized",
      source: {
        path: $challenge_dir,
        present: $source_present,
        read_only_expected: true,
        mount_target: $mount_target,
        mount_options: $mount_options,
        mount_read_only: $mount_read_only,
        writable_override_used: $writable_override_used
      },
      work: {
        path: $work_dir,
        copy_strategy: "fresh-work-exact"
      },
      inventory: {
        algorithm: "sha256",
        path: $inventory_path,
        digest: $inventory_digest,
        file_count: $file_count,
        total_bytes: $total_bytes,
        excludes: [".ctf", ".ctfos"],
        symlink_policy: "relative-internal-regular-file"
      },
      tree: {
        format: "ctf-tree-v1-nul",
        path: $tree_path,
        digest: $tree_digest,
        covers: ["path", "type", "mode", "content", "symlink_target"]
      },
      initialized_at: $initialized_at
    }' >"${metadata_tmp}"

  chmod 0644 "${inventory_tmp}" "${tree_tmp}" "${metadata_tmp}"
  mv -f -- "${inventory_tmp}" "${inventory_path}"
  inventory_tmp=''
  mv -f -- "${tree_tmp}" "${tree_path}"
  tree_tmp=''
  mv -f -- "${metadata_tmp}" "${metadata_path}"
  metadata_tmp=''
  cleanup
  trap - EXIT
fi

if ((lock_fd_open)); then
  flock -u 9
  exec 9>&-
fi

cd -- "${work_dir}"
exec "$@"
