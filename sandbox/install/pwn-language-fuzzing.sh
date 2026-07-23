#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

ATHERIS_VERSION=3.0.0
ATHERIS_X86_64_SHA256=8a5c8a781467c187da40fd29139784193e2647058831f837f675d0bb8cbd8746
ATHERIS_SOURCE_SHA256=5aa8d339ec4b49d6fb7c8b65e63e624ac522be9ecfacffe8639dcf609f0105a6
RUSTUP_VERSION=1.28.2
RUSTUP_X86_64_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
RUSTUP_AARCH64_SHA256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
RUST_NIGHTLY=2026-06-10
RUST_NIGHTLY_MANIFEST_SHA256=62894133face6c10c32614e86b43483e010652dcd5d543f51a5e7ec1c6a68fa8
CARGO_FUZZ_VERSION=0.13.2
CARGO_FUZZ_SHA256=5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2
LIBFUZZER_SYS_VERSION=0.4.13
LIBFUZZER_SYS_SHA256=a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2

architecture="$(dpkg --print-architecture)"
case "$architecture" in
  amd64)
    rust_host=x86_64-unknown-linux-gnu
    rustup_sha256="$RUSTUP_X86_64_SHA256"
    pip_install \
      "https://files.pythonhosted.org/packages/da/15/cf109e2e8696a54c8c4bc3ef79a79bec32361eceb64eaa36690a682e83a9/atheris-${ATHERIS_VERSION}-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl#sha256=${ATHERIS_X86_64_SHA256}"
    ;;
  arm64)
    # Upstream publishes no arm64 wheel. Keep the same pinned source release
    # for the architecture that cargo-fuzz and Jazzer support natively.
    rust_host=aarch64-unknown-linux-gnu
    rustup_sha256="$RUSTUP_AARCH64_SHA256"
    download_sha256 \
      "https://codeload.github.com/google/atheris/tar.gz/refs/tags/${ATHERIS_VERSION}" \
      /tmp/atheris.tar.gz "$ATHERIS_SOURCE_SHA256"
    mkdir -p /tmp/atheris
    tar -xzf /tmp/atheris.tar.gz -C /tmp/atheris --strip-components=1
    CLANG_BIN=/usr/bin/clang pip_install /tmp/atheris
    ;;
  *)
    echo "unsupported fuzzing tool architecture: $architecture" >&2
    exit 1
    ;;
esac

export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo-install
download_sha256 \
  "https://static.rust-lang.org/dist/${RUST_NIGHTLY}/channel-rust-nightly.toml" \
  /tmp/channel-rust-nightly.toml "$RUST_NIGHTLY_MANIFEST_SHA256"
download_sha256 \
  "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rust_host}/rustup-init" \
  /tmp/rustup-init "$rustup_sha256"
chmod 0755 /tmp/rustup-init
/tmp/rustup-init -y --no-modify-path --profile minimal \
  --default-toolchain "nightly-${RUST_NIGHTLY}"
ln -s \
  "/opt/rustup/toolchains/nightly-${RUST_NIGHTLY}-${rust_host}" \
  /opt/rust-toolchain

download_sha256 \
  "https://static.crates.io/crates/cargo-fuzz/cargo-fuzz-${CARGO_FUZZ_VERSION}.crate" \
  /tmp/cargo-fuzz.crate "$CARGO_FUZZ_SHA256"
mkdir -p /tmp/cargo-fuzz
tar -xzf /tmp/cargo-fuzz.crate -C /tmp/cargo-fuzz --strip-components=1
CARGO_NET_OFFLINE=false /opt/cargo-install/bin/cargo install \
  --path /tmp/cargo-fuzz --locked --root /tmp/cargo-fuzz-install
install -m 0755 /tmp/cargo-fuzz-install/bin/cargo-fuzz /usr/local/bin/cargo-fuzz

# A new `cargo fuzz init` project depends on libfuzzer-sys. Vendor the exact
# crate graph so the first target can compile with the sandbox network disabled.
mkdir -p /tmp/libfuzzer-vendor-seed/src /opt/cargo-fuzz-vendor
printf '%s\n' \
  '[package]' \
  'name = "ctf-os-libfuzzer-vendor-seed"' \
  'version = "0.0.0"' \
  'edition = "2021"' \
  '' \
  '[dependencies]' \
  "libfuzzer-sys = \"=${LIBFUZZER_SYS_VERSION}\"" \
  >/tmp/libfuzzer-vendor-seed/Cargo.toml
printf '%s\n' 'pub fn seed() {}' >/tmp/libfuzzer-vendor-seed/src/lib.rs
CARGO_NET_OFFLINE=false /opt/cargo-install/bin/cargo generate-lockfile \
  --manifest-path /tmp/libfuzzer-vendor-seed/Cargo.toml
CARGO_NET_OFFLINE=false /opt/cargo-install/bin/cargo vendor --versioned-dirs \
  --manifest-path /tmp/libfuzzer-vendor-seed/Cargo.toml \
  /opt/cargo-fuzz-vendor >/tmp/cargo-vendor-config
libfuzzer_archive="$(
  find /opt/cargo-install/registry/cache -type f \
    -name "libfuzzer-sys-${LIBFUZZER_SYS_VERSION}.crate" -print -quit
)"
[[ -n "$libfuzzer_archive" ]]
printf '%s  %s\n' "$LIBFUZZER_SYS_SHA256" "$libfuzzer_archive" \
  | sha256sum --check --strict -
chmod -R a+rX /opt/rustup /opt/cargo-fuzz-vendor

for command in cargo cargo-fuzz rustc; do require_command "$command"; done
for module in atheris boofuzz; do require_import "$module"; done
python3 -c 'from importlib.metadata import version; assert version("atheris") == "3.0.0"; assert version("boofuzz") == "0.4.2"'
rustc --version | grep -F 'rustc 1.98.0-nightly (beae78130 2026-06-09)'
cargo-fuzz --version | grep -F "cargo-fuzz ${CARGO_FUZZ_VERSION}"
rm -rf /tmp/atheris /tmp/atheris.tar.gz /tmp/rustup-init \
  /tmp/channel-rust-nightly.toml /tmp/cargo-fuzz /tmp/cargo-fuzz.crate \
  /tmp/cargo-fuzz-install /tmp/libfuzzer-vendor-seed /tmp/cargo-vendor-config \
  /opt/cargo-install
