#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s /challenge/EVIDENCE\n' "${0##*/}" >&2
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

run_to_file() {
  local destination="$1"
  local status
  shift
  prepare_output_file "$destination"
  if timeout 60 "$@" </dev/null >"$destination" 2>&1; then
    return 0
  else
    status=$?
  fi
  printf '\n[command exited with status %d]\n' "$status" >>"$destination"
  return 0
}

[[ $# -eq 1 ]] || usage
[[ -f "$1" ]] || {
  printf 'error: input is not a regular file: %s\n' "$1" >&2
  exit 2
}

target="$(realpath -e -- "$1")"
output_dir="/work/forensic"
prepare_output_dir
prepare_output_file "${output_dir}/summary.txt"
mime_type="$(file -b --mime-type -- "$target")"

{
  printf '[file]\n'
  file -- "$target"
  printf '\n[mime]\n%s\n' "$mime_type"
  printf '\n[sha256]\n'
  sha256sum -- "$target"
} >"${output_dir}/summary.txt"

run_to_file "${output_dir}/metadata.json" exiftool -json "$target"
run_to_file "${output_dir}/binwalk.txt" binwalk "$target"
run_to_file "${output_dir}/strings-ascii.txt" strings -a -n 4 -- "$target"
run_to_file "${output_dir}/strings-utf16le.txt" strings -a -el -n 4 -- "$target"

if command -v ktext >/dev/null 2>&1; then
  run_to_file "${output_dir}/strings-korean.txt" ktext "$target"
fi

case "$mime_type" in
  image/*)
    prepare_output_file "${output_dir}/ocr.log"
    prepare_output_file "${output_dir}/ocr-kor-eng.txt"
    run_to_file "${output_dir}/ocr.log" \
      tesseract "$target" "${output_dir}/ocr-kor-eng" -l kor+eng --psm 6
    ;;
esac

case "${target,,}" in
  *.hwp)
    run_to_file "${output_dir}/hwp-text.txt" hwp5txt "$target"
    ;;
  *.pcap|*.pcapng|*.cap)
    run_to_file "${output_dir}/pcap-protocols.txt" tshark -n -r "$target" -q -z io,phs
    ;;
  *.zip|*.7z|*.rar|*.tar|*.tgz|*.gz|*.bz2|*.xz)
    run_to_file "${output_dir}/archive-list.txt" 7z l -p- "$target"
    ;;
esac

printf 'forensic triage saved: %s\n' "${output_dir}/summary.txt"
