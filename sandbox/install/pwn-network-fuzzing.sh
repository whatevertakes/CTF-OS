#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

AFLNET_COMMIT=96032f86d0005dfeeb41ea7b31103f1d1ff8f168
AFLNET_SHA256=4c8c1c47d6b1beefceb74b56a1870e5a86e3b3d87389f6b8cde4d2ca9cca9ead
STATEAFL_COMMIT=d923e22f7b2688db45b08f3fa3a29a566e7ff3a4
STATEAFL_SHA256=b0479e36d1259cfd0d6e04f10ccd8f012743ef8e28d16163acd1377331c13784

apt_install graphviz-dev libcap-dev

build_network_fuzzer() {
  local name="$1" url="$2" archive="$3" sha256="$4" target="$5"
  download_sha256 "$url" "$archive" "$sha256"
  mkdir -p "$target"
  tar -xzf "$archive" -C "$target" --strip-components=1
  (cd "$target" && make clean && make -j2 all)

  # These projects document AFL_TRACE_PC as the fallback for newer LLVM.
  # clang 14 removed the old internal block-threshold option while retaining
  # trace-pc-guard itself, so remove only that obsolete compiler argument.
  sed -i \
    '/cc_params\[cc_par_cnt++\] = "-mllvm";/,+1d' \
    "$target/llvm_mode/afl-clang-fast.c"
  if [[ "$name" == "StateAFL" ]]; then
    # StateAFL combines its state tracer with Debian's non-PIC static
    # libstdc++. Its compiler wrapper must therefore link target executables
    # as non-PIE, matching the upstream toolchain assumptions.
    sed -i \
      '/if (maybe_linking) {/a\    cc_params[cc_par_cnt++] = "-no-pie";' \
      "$target/llvm_mode/afl-clang-fast.c"
  fi
  (
    cd "$target/llvm_mode"
    AFL_TRACE_PC=1 CC=/usr/bin/clang-14 CXX=/usr/bin/clang++-14 make -j2
  )

  test -x "$target/afl-fuzz"
  test -x "$target/afl-showmap"
  test -x "$target/afl-clang-fast"
  rm -f "$archive"
  printf '%s=READY\n' "$name"
}

build_network_fuzzer \
  AFLNet \
  "https://codeload.github.com/aflnet/aflnet/tar.gz/${AFLNET_COMMIT}" \
  /tmp/aflnet.tar.gz "$AFLNET_SHA256" /opt/aflnet
build_network_fuzzer \
  StateAFL \
  "https://codeload.github.com/StateAFL/StateAFL/tar.gz/${STATEAFL_COMMIT}" \
  /tmp/stateafl.tar.gz "$STATEAFL_SHA256" /opt/stateafl
