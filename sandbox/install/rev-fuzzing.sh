#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

JAZZER_VERSION=0.30.0
JAZZER_X86_64_SHA256=6eeaf0026d75599b07527d93b576593ce847cfca8b337a579971a5a9cdf792d0
JAZZER_ARM64_SHA256=16636a4d3e98f1d3a7fcf59d4ab37f5be1d1ad6df9d94d5c3ca8de644838e369

case "$(dpkg --print-architecture)" in
  amd64)
    jazzer_arch=x86-64
    jazzer_sha256="$JAZZER_X86_64_SHA256"
    ;;
  arm64)
    jazzer_arch=arm64
    jazzer_sha256="$JAZZER_ARM64_SHA256"
    ;;
  *)
    echo "unsupported Jazzer architecture: $(dpkg --print-architecture)" >&2
    exit 1
    ;;
esac

download_sha256 \
  "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v${JAZZER_VERSION}/jazzer-linux-${jazzer_arch}.tar.gz" \
  /tmp/jazzer.tar.gz "$jazzer_sha256"
mkdir -p /opt/jazzer
tar -xzf /tmp/jazzer.tar.gz -C /opt/jazzer
chmod 0755 /opt/jazzer/jazzer
ln -s /opt/jazzer/jazzer /usr/local/bin/jazzer

require_command java
require_command javac
require_command jazzer
test -s /opt/jazzer/jazzer_standalone.jar
java -version 2>&1 | grep -q 'version "21\.'
jazzer --version 2>&1 | grep -F "Jazzer v${JAZZER_VERSION}"
rm -f /tmp/jazzer.tar.gz
