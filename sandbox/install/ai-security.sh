#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

pip_install_locked \
  /opt/ctf-os/requirements-lock/ai-security.txt \
  --extra-index-url https://download.pytorch.org/whl/cu126
