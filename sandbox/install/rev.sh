#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

RADARE2_VERSION=5.9.8
JADX_VERSION=1.5.1
UPX_VERSION=4.2.4
WASMTIME_VERSION=24.0.0
RADARE2_SHA256=e45e4fd342f04b2e00363bc1b68cc375c1cf36041085d3d59caa7a3b7be43836
JADX_SHA256=12fd966431903b8e15c36e5007f19343475be7d8f2a55f082e7a929eeabc937e
UPX_SHA256=75cab4e57ab72fb4585ee45ff36388d280c7afd72aa03e8d4b9c3cbddb474193
WASMTIME_SHA256=27b4dff2ec7ab3148c73504f029f281bb78e0cea45d978f74e9f8c1d5585f8e6

/opt/ctf-os/install/binary-runtime.sh

apt_install \
  gdb gdb-multiarch apktool wabt mono-runtime \
  qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
  ovmf qemu-efi-aarch64 qemu-efi-arm seabios u-boot-qemu \
  build-essential meson ninja-build pkg-config libzip-dev liblz4-dev libssl-dev \
  ocl-icd-libopencl1
pip_install_locked /opt/ctf-os/requirements-lock/rev.txt
register_python_library_dirs nvidia.cuda_nvrtc nvidia.cuda_runtime

download_sha256 "https://github.com/radareorg/radare2/archive/refs/tags/${RADARE2_VERSION}.tar.gz" /tmp/radare2.tar.gz "$RADARE2_SHA256"
mkdir /tmp/radare2 && tar -xzf /tmp/radare2.tar.gz -C /tmp/radare2 --strip-components=1
(cd /tmp/radare2 && ./configure --prefix=/usr/local && make -j2 && make install)
# Register the installed shared libraries so r2 works with a clean worker
# environment instead of depending on LD_LIBRARY_PATH.
ldconfig

download_sha256 "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" /tmp/jadx.zip "$JADX_SHA256"
unzip -q /tmp/jadx.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

download_sha256 "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" /tmp/upx.tar.xz "$UPX_SHA256"
tar -xJf /tmp/upx.tar.xz -C /tmp
install -m 0755 "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx

download_sha256 "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" /tmp/wasmtime.tar.xz "$WASMTIME_SHA256"
tar -xJf /tmp/wasmtime.tar.xz -C /tmp
install -m 0755 "/tmp/wasmtime-v${WASMTIME_VERSION}-x86_64-linux/wasmtime" /usr/local/bin/wasmtime
rm -rf /tmp/radare2* /tmp/jadx.zip /tmp/upx* /tmp/wasmtime*

for command in r2 gdb gdb-multiarch jadx apktool wasm-objdump upx wasmtime mono qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 qemu-system-riscv64 qemu-img; do require_command "$command"; done
for module in angr unicorn capstone keystone lief pefile elftools pyopencl cupy; do require_import "$module"; done
python3 -c 'import ctypes; ctypes.CDLL("libnvrtc.so.12"); ctypes.CDLL("libcudart.so.12")'
/usr/local/bin/ctf-os-binary-runtime-smoke
/usr/local/bin/ctf-os-system-qemu-smoke
