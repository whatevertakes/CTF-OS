#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

STEGSEEK_VERSION=0.6
apt_install \
  sleuthkit foremost libimage-exiftool-perl binwalk tshark tcpdump testdisk dcfldd \
  xfsprogs e2fsprogs ntfs-3g steghide imagemagick tesseract-ocr pngcheck \
  ffmpeg sox libzbar0 zbar-tools libgl1 libglib2.0-0
pip_install -r /opt/ctf-os/requirements/forensic.txt
if ! command -v vol >/dev/null && command -v vol.py >/dev/null; then ln -s "$(command -v vol.py)" /usr/local/bin/vol; fi
gem install zsteg --version 0.2.13 --no-document

download "https://github.com/RickdeJager/stegseek/releases/download/v${STEGSEEK_VERSION}/stegseek_${STEGSEEK_VERSION}-1.deb" /tmp/stegseek.deb
apt-get update
apt-get install -y --no-install-recommends /tmp/stegseek.deb
rm -rf /var/lib/apt/lists/* /tmp/stegseek.deb

for command in vol mmls fls icat foremost exiftool binwalk tshark tcpdump testdisk photorec dcfldd steghide stegseek zsteg convert tesseract pngcheck ffmpeg sox; do require_command "$command"; done
for module in volatility3 scapy pyshark oletools pdfminer magic PIL numpy scipy capstone; do require_import "$module"; done
