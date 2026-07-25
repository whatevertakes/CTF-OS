#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

apt_install \
  ffmpeg sox imagemagick tesseract-ocr tshark binwalk libimage-exiftool-perl \
  graphviz parallel podman uidmap slirp4netns fuse-overlayfs zbar-tools libzbar0 barcode \
  php-cli lua5.4 perl nodejs npm libgl1 libglib2.0-0
pip_install_locked /opt/ctf-os/requirements-lock/misc.txt
pip_install_locked \
  /opt/ctf-os/requirements-lock/torch-cpu.txt \
  --index-url https://download.pytorch.org/whl/cpu

# The sandbox keeps no-new-privileges, so setuid newuidmap cannot be used.
# A single-ID rootless mapping is sufficient for local OCI inspection and
# avoids granting a subordinate host-ID range to nested containers.
sed -i '/^ctf:/d' /etc/subuid
sed -i '/^ctf:/d' /etc/subgid

for command in ffmpeg sox convert tesseract tshark binwalk exiftool dot parallel podman zbarimg barcode php lua perl node npm ares; do require_command "$command"; done
for module in torch sklearn cv2 pandas PIL numpy scipy networkx sympy z3 scapy qrcode; do require_import "$module"; done
python3 -c 'import torch; assert torch.tensor([2,3]).sum().item() == 5'
ares --help >/dev/null
podman --version
