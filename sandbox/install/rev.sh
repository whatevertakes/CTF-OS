#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

RADARE2_VERSION=6.1.8
JADX_VERSION=1.5.6
APKTOOL_VERSION=3.0.3
UPX_VERSION=5.2.0
WASMTIME_VERSION=47.0.2
RADARE2_SHA256=5b5ca179846c571a171a117d0a70e67cf114eecc66370fd030656b4f5bc1919b
JADX_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
APKTOOL_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
UPX_SHA256=3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1
WASMTIME_SHA256=9ec85751649139711b6a5061c4f48a41412bf9b1ab98a08b9924ca73f22ca575

/opt/ctf-os/install/binary-runtime.sh

apt_install \
  gdb gdb-multiarch apktool wabt mono-runtime \
  qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
  ovmf qemu-efi-aarch64 qemu-efi-arm seabios u-boot-qemu \
  build-essential meson ninja-build pkg-config libzip-dev liblz4-dev libssl-dev \
  ocl-icd-libopencl1
pip_install_locked /opt/ctf-os/requirements-lock/rev.txt
register_python_library_dirs nvidia.cuda_nvrtc nvidia.cuda_runtime

download_sha256 "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-${RADARE2_VERSION}.tar.xz" /tmp/radare2.tar.xz "$RADARE2_SHA256"
mkdir /tmp/radare2 && tar -xJf /tmp/radare2.tar.xz -C /tmp/radare2 --strip-components=1
(cd /tmp/radare2 && ./configure --prefix=/usr/local && make -j2 && make install)
# Register the installed shared libraries so r2 works with a clean worker
# environment instead of depending on LD_LIBRARY_PATH.
ldconfig

download_sha256 "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" /tmp/jadx.zip "$JADX_SHA256"
unzip -q /tmp/jadx.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

mkdir -p /opt/apktool
download_sha256 \
  "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
  /opt/apktool/apktool.jar "$APKTOOL_SHA256"
ln -s /usr/bin/apktool /usr/local/bin/apktool2

download_sha256 "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" /tmp/upx.tar.xz "$UPX_SHA256"
tar -xJf /tmp/upx.tar.xz -C /tmp
install -m 0755 "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx

download_sha256 "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" /tmp/wasmtime.tar.xz "$WASMTIME_SHA256"
tar -xJf /tmp/wasmtime.tar.xz -C /tmp
install -m 0755 "/tmp/wasmtime-v${WASMTIME_VERSION}-x86_64-linux/wasmtime" /usr/local/bin/wasmtime
rm -rf /tmp/radare2* /tmp/jadx.zip /tmp/upx* /tmp/wasmtime*

for command in r2 gdb gdb-multiarch jadx apktool apktool2 wasm-objdump upx wasmtime mono qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 qemu-system-riscv64 qemu-img; do require_command "$command"; done
for module in angr unicorn capstone keystone lief pefile elftools pyopencl cupy; do require_import "$module"; done
python3 -c 'import ctypes; ctypes.CDLL("libnvrtc.so.12"); ctypes.CDLL("libcudart.so.12")'
/usr/local/bin/ctf-os-binary-runtime-smoke
/usr/local/bin/ctf-os-system-qemu-smoke
