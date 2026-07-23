#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

WAYBACKURLS_COMMIT=8d27cf3e3031de01179e8ba9127e968eb01008e9
THEHARVESTER_COMMIT=d36e326f7738c821900332af3f058c60e69149a3
THEHARVESTER_SHA256=606898a3f800485116abcece48853eb3736f8aac16168888e4bfcc67df21e8b4
apt_install \
  whois dnsutils traceroute chromium chromium-driver libimage-exiftool-perl imagemagick \
  tesseract-ocr ffmpeg git-lfs poppler-utils golang-go libgl1 libglib2.0-0
pip_install -r /opt/ctf-os/requirements/osint.txt

python3 -m venv /opt/sherlock-venv
/opt/sherlock-venv/bin/pip install --no-cache-dir sherlock-project==0.16.0
ln -s /opt/sherlock-venv/bin/sherlock /usr/local/bin/sherlock

python3 -m venv /opt/maigret-venv
/opt/maigret-venv/bin/pip install --no-cache-dir maigret==0.6.3
ln -s /opt/maigret-venv/bin/maigret /usr/local/bin/maigret

python3 -m venv /opt/holehe-venv
/opt/holehe-venv/bin/pip install --no-cache-dir holehe==1.61
ln -s /opt/holehe-venv/bin/holehe /usr/local/bin/holehe

python3 -m venv /opt/theharvester-venv
/opt/theharvester-venv/bin/pip install --no-cache-dir \
  "https://github.com/laramies/theHarvester/archive/${THEHARVESTER_COMMIT}.tar.gz#sha256=${THEHARVESTER_SHA256}"
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
