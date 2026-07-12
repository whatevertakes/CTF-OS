#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

output_dir="dist/team-bundle"
ref="HEAD"

usage() {
  echo "usage: scripts/build_team_bundle.sh [--output-dir DIR] [--ref GIT_REF]"
}

while (($#)); do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --ref)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      ref="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }
command -v gzip >/dev/null 2>&1 || { echo "gzip is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

commit="$(git rev-parse --verify "${ref}^{commit}")"
short_commit="$(git rev-parse --short=12 "$commit")"

if [[ "$ref" == "HEAD" ]] && [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "tracked files are modified; commit them before building a team bundle" >&2
  echo "the bundle intentionally contains committed source only" >&2
  exit 1
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
archive_name="ctf-os-team-${short_commit}.tar.gz"
archive_path="$output_dir/$archive_name"
checksum_path="$archive_path.sha256"
temporary="$(mktemp -d "$output_dir/.ctf-os-bundle.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

git archive --format=tar --prefix=CTF-OS/ --output="$temporary/source.tar" "$commit"
gzip -n -9 < "$temporary/source.tar" > "$temporary/$archive_name"

tar -tzf "$temporary/$archive_name" > "$temporary/members.txt"
for required in CTF-OS/README.md CTF-OS/scripts/deploy_ctf_os.sh CTF-OS/config.example.yaml; do
  grep -Fxq "$required" "$temporary/members.txt" || {
    echo "bundle is missing required member: $required" >&2
    exit 1
  }
done

if grep -E '(^|/)(\.env($|\.)|local\..*\.ya?ml$|config\.yaml$|.*\.(db|sqlite|sqlite3|pem|key)$|id_(rsa|ed25519)$|flag\.txt$|benchmarks/results/)' "$temporary/members.txt" >/dev/null; then
  echo "bundle contains a forbidden local runtime or secret-shaped path" >&2
  exit 1
fi

mv "$temporary/$archive_name" "$archive_path"
(
  cd "$output_dir"
  sha256sum "$archive_name" > "${archive_name}.sha256"
)

echo "team bundle: $archive_path"
echo "checksum: $checksum_path"
echo "source commit: $commit"
