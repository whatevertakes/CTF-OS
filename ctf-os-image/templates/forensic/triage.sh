#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s [--output-dir /work/forensic] /challenge/EVIDENCE\n' \
    "${0##*/}" >&2
  exit 2
}

prepare_output_dir() {
  local output_parent
  output_parent=$(dirname -- "$output_dir")
  [[ "$output_dir" == /* && "$output_dir" != / ]] || {
    printf 'error: output directory must be an absolute child path\n' >&2
    exit 1
  }
  [[ -d "$output_parent" && ! -L "$output_parent" ]] || {
    printf 'error: unsafe output parent: %s\n' "$output_parent" >&2
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
  if (ulimit -f 16384; timeout --signal=TERM --kill-after=2s 60 "$@") \
      </dev/null >"$destination" 2>&1; then
    return 0
  else
    status=$?
  fi
  printf '\n[command exited with status %d]\n' "$status" >>"$destination"
  return 0
}

output_dir=/work/forensic
if [[ $# -eq 3 && $1 == --output-dir ]]; then
  output_dir=$2
  shift 2
fi
[[ $# -eq 1 ]] || usage
[[ -f "$1" && ! -L "$1" ]] || {
  printf 'error: input is not a regular non-symlink file: %s\n' "$1" >&2
  exit 2
}

target="$(realpath -e -- "$1")"
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
  *.evtx)
    run_to_file "${output_dir}/evtx-info.txt" evtxinfo "$target"
    run_to_file "${output_dir}/evtx-records.xml" evtxexport "$target"
    ;;
  *.hive|*.regf|*/ntuser.dat|*/usrclass.dat|*/sam|*/security|*/software|*/system)
    run_to_file "${output_dir}/registry-info.txt" regfinfo "$target"
    run_to_file "${output_dir}/registry-export.txt" regfexport "$target"
    ;;
  *.e01|*.ex01)
    run_to_file "${output_dir}/ewf-info.txt" ewfinfo "$target"
    run_to_file "${output_dir}/ewf-verify.txt" ewfverify -q "$target"
    ;;
  *.pf)
    run_to_file "${output_dir}/prefetch-info.txt" sccainfo "$target"
    ;;
  *.doc|*.docm|*.docx|*.dot|*.dotm|*.dotx|*.xls|*.xlsb|*.xlsm|*.xlsx|*.ppt|*.pptm|*.pptx)
    run_to_file "${output_dir}/office-indicators.txt" oleid "$target"
    run_to_file "${output_dir}/office-vba.txt" olevba "$target"
    ;;
  *.pdf)
    run_to_file "${output_dir}/pdf-indicators.txt" pdfid "$target"
    run_to_file "${output_dir}/pdf-check.txt" qpdf --check "$target"
    run_to_file "${output_dir}/pdf-attachments.txt" pdfdetach -list "$target"
    ;;
  *.sqlite|*.sqlite3|*.db|*/history)
    run_to_file "${output_dir}/sqlite-schema.json" \
      ctf-sqlite-readonly "$target" --schema --max-rows 1000
    case "${target,,}" in
      */history|*/places.sqlite)
        run_to_file "${output_dir}/browser-timeline-summary.json" \
          /opt/ctf-templates/forensic/browser_timeline.py "$target" \
          --output-dir "$output_dir"
        ;;
    esac
    ;;
  *.pcap|*.pcapng|*.cap)
    run_to_file "${output_dir}/pcap-protocols.txt" tshark -n -r "$target" -q -z io,phs
    ;;
  *.qcow|*.qcow2|*.vdi|*.vhd|*.vhdx|*.vmdk)
    run_to_file "${output_dir}/virtual-disk-info.json" \
      qemu-img info --output=json "$target"
    ;;
  *.zip|*.7z|*.rar|*.tar|*.tgz|*.gz|*.bz2|*.xz)
    run_to_file "${output_dir}/archive-list.txt" 7z l -p- "$target"
    ;;
esac

printf 'forensic triage saved: %s\n' "${output_dir}/summary.txt"
