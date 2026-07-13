#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

WAYBACKURLS_COMMIT=8d27cf3e3031de01179e8ba9127e968eb01008e9
apt_install \
  whois dnsutils traceroute chromium chromium-driver libimage-exiftool-perl imagemagick \
  tesseract-ocr ffmpeg git-lfs poppler-utils golang-go libgl1 libglib2.0-0
pip_install -r /opt/ctf-os/requirements/osint.txt
GOBIN=/usr/local/bin go install "github.com/tomnomnom/waybackurls@${WAYBACKURLS_COMMIT}"
rm -rf /root/go /root/.cache/go-build

for command in whois dig nslookup host traceroute chromium exiftool convert tesseract ffmpeg yt-dlp git-lfs pdftotext waybackurls; do require_command "$command"; done
for module in requests httpx bs4 lxml playwright PIL cv2 pandas whois dns geopy exifread pdfminer; do require_import "$module"; done
runuser -u ctf -- chromium --headless --no-sandbox --disable-gpu --dump-dom 'data:text/html,<title>ctf-os</title>' | grep -q ctf-os
