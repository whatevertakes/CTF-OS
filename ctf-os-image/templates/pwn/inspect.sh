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
output_dir="/work/pwn"
report="${output_dir}/inspect.txt"
prepare_output_dir
prepare_output_file "$report"
prepare_output_file "${output_dir}/strings.txt"
prepare_output_file "${output_dir}/strings.error"

{
  printf '[file]\n'
  timeout 10 file -- "$target" || true
  printf '\n[sha256]\n'
  timeout 10 sha256sum -- "$target" || true
  printf '\n[checksec]\n'
  timeout 20 checksec --file="$target" || true
  printf '\n[elf-header]\n'
  timeout 20 readelf -hW -- "$target" || true
  printf '\n[program-headers]\n'
  timeout 20 readelf -lW -- "$target" || true
  printf '\n[dynamic-section]\n'
  timeout 20 readelf -dW -- "$target" || true
  printf '\n[imports-and-symbols]\n'
  timeout 30 readelf -sW -- "$target" || true
} </dev/null >"$report" 2>&1

timeout 30 strings -a -n 4 -- "$target" \
  </dev/null >"${output_dir}/strings.txt" 2>"${output_dir}/strings.error" || true

printf 'pwn inspection saved: %s\n' "$report"
