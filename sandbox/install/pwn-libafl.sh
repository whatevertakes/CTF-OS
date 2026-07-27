#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

LIBAFL_VERSION=0.15.4
LIBAFL_SHA256=02b83725a28a0c7ba38efe1ed767277660fc70f701156453aaab471ce953c4d2
LIBAFL_FUZZ_LOCK_SHA256=20c3ccb79ef376f5623120451c80f37413fed5fbcc7e0e83b0ead533467cb5f4

download_sha256 \
  "https://codeload.github.com/AFLplusplus/LibAFL/tar.gz/refs/tags/${LIBAFL_VERSION}" \
  /tmp/libafl.tar.gz "$LIBAFL_SHA256"
mkdir -p /opt/libafl /opt/libafl-vendor /tmp/libafl-cargo
tar -xzf /tmp/libafl.tar.gz -C /opt/libafl --strip-components=1
export CARGO_HOME=/tmp/libafl-cargo
export CARGO_NET_OFFLINE=false
export CARGO_TARGET_DIR=/tmp/libafl-target
# Rust nightly 1.98 added a standard-library as_slice candidate that collides
# with LibAFL 0.15.4's extension trait. It is warning-only and behavior remains
# unambiguous today; LibAFL promotes all warnings to errors.
export RUSTFLAGS="-A unstable-name-collisions -A unused-features"
(
  cd /opt/libafl
  /opt/rust-toolchain/bin/cargo generate-lockfile \
    --manifest-path fuzzers/forkserver/libafl-fuzz/Cargo.toml
  printf '%s  %s\n' \
    "$LIBAFL_FUZZ_LOCK_SHA256" \
    fuzzers/forkserver/libafl-fuzz/Cargo.lock \
    | sha256sum --check --strict -
  /opt/rust-toolchain/bin/cargo build --release --locked \
    --manifest-path fuzzers/forkserver/libafl-fuzz/Cargo.toml
  mkdir -p .cargo
  /opt/rust-toolchain/bin/cargo vendor --locked --versioned-dirs \
    --manifest-path fuzzers/forkserver/libafl-fuzz/Cargo.toml \
    /opt/libafl-vendor >.cargo/config.toml
)
install -m 0755 \
  /tmp/libafl-target/release/libafl-fuzz /usr/local/bin/libafl-fuzz
chmod -R a+rX /opt/libafl /opt/libafl-vendor
require_command libafl-fuzz
libafl-fuzz --help >/dev/null
rm -rf /tmp/libafl.tar.gz /tmp/libafl-cargo /tmp/libafl-target
