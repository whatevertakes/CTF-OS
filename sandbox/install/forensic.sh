#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

STEGSEEK_VERSION=0.6
STEGSEEK_SHA256=7218c0e0d0cc81e31678eac6d63d1af46eccd6a0d4a9299e3b68b11e7bfc92f3
BULK_EXTRACTOR_VERSION=2.1.1
BULK_EXTRACTOR_SHA256=0cd57c743581a66ea94d49edac2e89210c80a2a7cc90dd254d56940b3d41b7f7
apt_install \
  sleuthkit foremost libimage-exiftool-perl binwalk tshark tcpdump testdisk dcfldd \
  xfsprogs e2fsprogs ntfs-3g steghide imagemagick tesseract-ocr pngcheck \
  ffmpeg sox libzbar0 zbar-tools libgl1 libglib2.0-0 \
  yara sqlite3 poppler-utils \
  g++ flex libabsl-dev libewf-dev libexpat1-dev libpcap-dev libpcre3-dev \
  libre2-dev libsqlite3-dev libssl-dev libtool libxml2-utils make pkg-config \
  zlib1g-dev
pip_install_locked /opt/ctf-os/requirements-lock/forensic.txt
if ! command -v vol >/dev/null && command -v vol.py >/dev/null; then ln -s "$(command -v vol.py)" /usr/local/bin/vol; fi
gem install zsteg --version 0.2.13 --no-document

download_sha256 \
  "https://github.com/simsong/bulk_extractor/releases/download/v${BULK_EXTRACTOR_VERSION}/bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" \
  /tmp/bulk-extractor.tar.gz "$BULK_EXTRACTOR_SHA256"
mkdir -p /tmp/bulk-extractor
tar -xzf /tmp/bulk-extractor.tar.gz -C /tmp/bulk-extractor --strip-components=1
(
  cd /tmp/bulk-extractor
  ./configure --prefix=/usr/local
  make -j2
  make install
)

download_sha256 "https://github.com/RickdeJager/stegseek/releases/download/v${STEGSEEK_VERSION}/stegseek_${STEGSEEK_VERSION}-1.deb" /tmp/stegseek.deb "$STEGSEEK_SHA256"
apt-get update
apt-get install -y --no-install-recommends /tmp/stegseek.deb
rm -rf \
  /var/lib/apt/lists/* /tmp/stegseek.deb \
  /tmp/bulk-extractor /tmp/bulk-extractor.tar.gz

for command in \
  vol mmls fls icat foremost exiftool binwalk tshark tcpdump testdisk photorec \
  dcfldd steghide stegseek zsteg convert tesseract pngcheck ffmpeg sox \
  yara bulk_extractor sqlite3 pdfinfo pdftotext olevba oleid rtfobj; do
  require_command "$command"
done
for module in volatility3 scapy pyshark oletools pdfminer magic PIL numpy scipy capstone; do require_import "$module"; done
stegseek --version
bulk_extractor --version | grep -Fx "bulk_extractor ${BULK_EXTRACTOR_VERSION}"
bulk_smoke="$(mktemp -d /tmp/ctf-os-bulk-extractor.XXXXXX)"
printf 'CTF OS forensic smoke test: analyst@example.com\n' >"$bulk_smoke/input.txt"
bulk_extractor -q -o "$bulk_smoke/output" "$bulk_smoke/input.txt"
grep -F 'analyst@example.com' "$bulk_smoke/output/email.txt"
rm -rf -- "$bulk_smoke"
