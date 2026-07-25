#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

CADO_NFS_COMMIT=90aec67f9a8f0badd0a20d1bbe4c1c2ed2e3c507
CADO_NFS_SHA256=4b4821009af9364abd16f4d45bd6dcb3aedeef3c8855f002389508a23e5c1841

apt_install \
  sagemath pari-gp gap maxima libgmp-dev libmpfr-dev libmpc-dev libecm-dev \
  libhwloc-dev libopenmpi-dev openmpi-bin python3-mpi4py \
  hashcat ocl-icd-libopencl1 pocl-opencl-icd
pip_install_locked /opt/ctf-os/requirements-lock/crypto.txt
pip_install_locked /opt/ctf-os/requirements-lock/cuda-nvrtc.txt
register_python_library_dirs nvidia.cuda_nvrtc
# Hashcat 6.2 loads the unversioned NVRTC soname with dlopen(), while NVIDIA's
# runtime wheel intentionally ships only libnvrtc.so.12.
link_python_library nvidia.cuda_nvrtc libnvrtc.so.12 libnvrtc.so
# Debian's GCL-backed Maxima needs a seccomp relaxation merely to start. Sage
# also ships an ECL-backed Maxima that works under the default sandbox policy.
ln -sf /usr/bin/maxima-sage /usr/local/bin/maxima
# RsaCtfTool pins an older HTTP/crypto stack. Keep that complete, hashed
# dependency graph in its own environment so both it and the common Python
# environment remain internally consistent.
python3 -m venv /opt/rsactftool-venv
venv_install_locked \
  /opt/rsactftool-venv /opt/ctf-os/requirements-lock/isolated/rsactftool.txt
/opt/rsactftool-venv/bin/pip check
ln -s /opt/rsactftool-venv/bin/RsaCtfTool /usr/local/bin/RsaCtfTool

download_sha256 "https://github.com/cado-nfs/cado-nfs/archive/${CADO_NFS_COMMIT}.tar.gz" /tmp/cado-nfs.tar.gz "$CADO_NFS_SHA256"
mkdir /tmp/cado-nfs && tar -xzf /tmp/cado-nfs.tar.gz -C /tmp/cado-nfs --strip-components=1
cmake -S /tmp/cado-nfs -B /tmp/cado-build -DCMAKE_BUILD_TYPE=Release
# This is the only source build with a large native graph. Six jobs is bounded
# below the supported pre-build host's 12 CPUs while avoiding a prohibitively
# long serial CADO build; profile builds themselves remain sequential.
cmake --build /tmp/cado-build --parallel 6
cmake --install /tmp/cado-build
ln -s /usr/local/bin/cado-nfs.py /usr/local/bin/cado-nfs
rm -rf /tmp/cado-nfs* /tmp/cado-build

for command in sage RsaCtfTool cado-nfs gp gap maxima hashcat ares; do require_command "$command"; done
hashcat --version
ares --help >/dev/null
RsaCtfTool --help >/dev/null
python3 -c 'import ctypes; ctypes.CDLL("libnvrtc.so")'
for module in z3 gmpy2 Crypto fpylll cysignals sympy cryptography ecdsa; do require_import "$module"; done
