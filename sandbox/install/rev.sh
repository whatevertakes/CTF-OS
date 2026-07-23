#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

RADARE2_VERSION=5.9.8
JADX_VERSION=1.5.1
UPX_VERSION=4.2.4
WASMTIME_VERSION=24.0.0

/opt/ctf-os/install/binary-runtime.sh

apt_install \
  gdb gdb-multiarch apktool wabt mono-runtime \
  qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
  ovmf qemu-efi-aarch64 qemu-efi-arm seabios u-boot-qemu \
  build-essential meson ninja-build pkg-config libzip-dev liblz4-dev libssl-dev \
  ocl-icd-libopencl1
pip_install -r /opt/ctf-os/requirements/rev.txt
register_python_library_dirs nvidia.cuda_nvrtc nvidia.cuda_runtime

download "https://github.com/radareorg/radare2/archive/refs/tags/${RADARE2_VERSION}.tar.gz" /tmp/radare2.tar.gz
mkdir /tmp/radare2 && tar -xzf /tmp/radare2.tar.gz -C /tmp/radare2 --strip-components=1
(cd /tmp/radare2 && ./configure --prefix=/usr/local && make -j2 && make install)
# Register the installed shared libraries so r2 works with a clean worker
# environment instead of depending on LD_LIBRARY_PATH.
ldconfig

download "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" /tmp/jadx.zip
unzip -q /tmp/jadx.zip -d /opt/jadx
ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

download "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" /tmp/upx.tar.xz
tar -xJf /tmp/upx.tar.xz -C /tmp
install -m 0755 "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx

download "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" /tmp/wasmtime.tar.xz
tar -xJf /tmp/wasmtime.tar.xz -C /tmp
install -m 0755 "/tmp/wasmtime-v${WASMTIME_VERSION}-x86_64-linux/wasmtime" /usr/local/bin/wasmtime
rm -rf /tmp/radare2* /tmp/jadx.zip /tmp/upx* /tmp/wasmtime*

for command in r2 gdb gdb-multiarch jadx apktool wasm-objdump upx wasmtime mono qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 qemu-system-riscv64 qemu-img; do require_command "$command"; done
for module in angr unicorn capstone keystone lief pefile elftools pyopencl cupy; do require_import "$module"; done
python3 -c 'import ctypes; ctypes.CDLL("libnvrtc.so.12"); ctypes.CDLL("libcudart.so.12")'
/usr/local/bin/ctf-os-binary-runtime-smoke
/usr/local/bin/ctf-os-system-qemu-smoke
