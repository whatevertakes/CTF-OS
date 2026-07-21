#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

CADO_NFS_COMMIT=90aec67f9a8f0badd0a20d1bbe4c1c2ed2e3c507
RSACTFTOOL_COMMIT=7c98848f1945de3e67a420871e8672f5ad9aa5d5

apt_install \
  sagemath pari-gp gap maxima libgmp-dev libmpfr-dev libmpc-dev libecm-dev \
  libhwloc-dev libopenmpi-dev openmpi-bin python3-mpi4py \
  hashcat ocl-icd-libopencl1 pocl-opencl-icd
# Debian's GCL-backed Maxima needs a seccomp relaxation merely to start. Sage
# also ships an ECL-backed Maxima that works under the default sandbox policy.
ln -sf /usr/bin/maxima-sage /usr/local/bin/maxima
pip_install -r /opt/ctf-os/requirements/crypto.txt
# RsaCtfTool's historical dependency caps would downgrade the hardened common
# HTTP/crypto layer. Its required runtime dependencies are pinned above.
pip_install --no-deps "https://github.com/RsaCtfTool/RsaCtfTool/archive/${RSACTFTOOL_COMMIT}.tar.gz"
if ! command -v RsaCtfTool >/dev/null && command -v RsaCtfTool.py >/dev/null; then ln -s "$(command -v RsaCtfTool.py)" /usr/local/bin/RsaCtfTool; fi

download "https://github.com/cado-nfs/cado-nfs/archive/${CADO_NFS_COMMIT}.tar.gz" /tmp/cado-nfs.tar.gz
mkdir /tmp/cado-nfs && tar -xzf /tmp/cado-nfs.tar.gz -C /tmp/cado-nfs --strip-components=1
cmake -S /tmp/cado-nfs -B /tmp/cado-build -DCMAKE_BUILD_TYPE=Release
# This is the only source build with a large native graph. Six jobs is bounded
# below the supported pre-build host's 12 CPUs while avoiding a prohibitively
# long serial CADO build; profile builds themselves remain sequential.
cmake --build /tmp/cado-build --parallel 6
cmake --install /tmp/cado-build
ln -s /usr/local/bin/cado-nfs.py /usr/local/bin/cado-nfs
rm -rf /tmp/cado-nfs* /tmp/cado-build

for command in sage RsaCtfTool cado-nfs gp gap maxima hashcat; do require_command "$command"; done
hashcat --version
for module in z3 gmpy2 Crypto fpylll cysignals sympy cryptography ecdsa; do require_import "$module"; done
