#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s /challenge/BINARY\n' "${0##*/}" >&2
  exit 2
}

prepare_output_dir() {
  [[ -d /work && ! -L /work ]] || {
    printf 'error: unsafe output parent: /work\n' >&2
    exit 1
  }
  if [[ -e "$output_dir" || -L "$output_dir" ]]; then
    [[ -d "$output_dir" && ! -L "$output_dir" ]] || {
      printf 'error: unsafe output directory: %s\n' "$output_dir" >&2
      exit 1
    }
  else
    mkdir -- "$output_dir"
  fi
}

prepare_output_file() {
  if [[ -e "$1" || -L "$1" ]]; then
    [[ -f "$1" && ! -L "$1" ]] || {
      printf 'error: refusing non-regular output artifact: %s\n' "$1" >&2
      exit 1
    }
  fi
}

[[ $# -eq 1 ]] || usage
[[ -f "$1" ]] || {
  printf 'error: input is not a regular file: %s\n' "$1" >&2
  exit 2
}

target="$(realpath -e -- "$1")"
output_dir="/work/rev"
prepare_output_dir
for artifact in \
  summary.txt strings-ascii.txt strings-ascii.error \
  strings-utf16le.txt strings-utf16le.error \
  strings-korean.txt strings-korean.error; do
  prepare_output_file "${output_dir}/${artifact}"
done

{
  printf '[file]\n'
  timeout 10 file -- "$target" || true
  printf '\n[sha256]\n'
  timeout 10 sha256sum -- "$target" || true
  printf '\n[rabin2-info]\n'
  timeout 30 rabin2 -I "$target" || true
  printf '\n[rabin2-imports]\n'
  timeout 30 rabin2 -i "$target" || true
  printf '\n[rabin2-symbols]\n'
  timeout 30 rabin2 -s "$target" || true
} </dev/null >"${output_dir}/summary.txt" 2>&1

timeout 30 strings -a -n 4 -- "$target" \
  </dev/null >"${output_dir}/strings-ascii.txt" 2>"${output_dir}/strings-ascii.error" || true
timeout 30 strings -a -el -n 4 -- "$target" \
  </dev/null >"${output_dir}/strings-utf16le.txt" 2>"${output_dir}/strings-utf16le.error" || true

if command -v ktext >/dev/null 2>&1; then
  timeout 60 ktext "$target" \
    </dev/null >"${output_dir}/strings-korean.txt" 2>"${output_dir}/strings-korean.error" || true
fi

printf 'reverse-engineering analysis saved: %s\n' "${output_dir}/summary.txt"
