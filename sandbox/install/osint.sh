#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

WAYBACKURLS_COMMIT=8d27cf3e3031de01179e8ba9127e968eb01008e9
apt_install \
  whois dnsutils traceroute chromium chromium-driver libimage-exiftool-perl imagemagick \
  tesseract-ocr ffmpeg git-lfs poppler-utils golang-go libgl1 libglib2.0-0
pip_install_locked /opt/ctf-os/requirements-lock/osint.txt

python3 -m venv /opt/sherlock-venv
venv_install_locked \
  /opt/sherlock-venv /opt/ctf-os/requirements-lock/isolated/sherlock.txt
ln -s /opt/sherlock-venv/bin/sherlock /usr/local/bin/sherlock

python3 -m venv /opt/maigret-venv
venv_install_locked \
  /opt/maigret-venv /opt/ctf-os/requirements-lock/isolated/maigret.txt
ln -s /opt/maigret-venv/bin/maigret /usr/local/bin/maigret

python3 -m venv /opt/holehe-venv
venv_install_locked \
  /opt/holehe-venv /opt/ctf-os/requirements-lock/isolated/holehe.txt
ln -s /opt/holehe-venv/bin/holehe /usr/local/bin/holehe

python3 -m venv /opt/theharvester-venv
venv_install_locked \
  /opt/theharvester-venv /opt/ctf-os/requirements-lock/isolated/theharvester.txt
ln -s /opt/theharvester-venv/bin/theHarvester /usr/local/bin/theHarvester

GOBIN=/usr/local/bin go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_COMMIT}"
rm -rf /root/go /root/.cache/go-build

for command in whois dig nslookup host traceroute chromium exiftool convert tesseract ffmpeg yt-dlp git-lfs pdftotext waybackurls sherlock maigret holehe theHarvester; do require_command "$command"; done
for module in requests httpx bs4 lxml playwright PIL cv2 pandas whois dns geopy exifread pdfminer; do require_import "$module"; done
runuser -u ctf -- chromium --headless --no-sandbox --disable-gpu --dump-dom 'data:text/html,<title>ctf-os</title>' | grep -q ctf-os
sherlock --help >/dev/null
maigret --help >/dev/null
holehe --help >/dev/null
theHarvester --help >/dev/null
