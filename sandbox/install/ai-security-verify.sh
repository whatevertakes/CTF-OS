#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

for command in modelscan fickling; do require_command "$command"; done
for module in h5py tensorflow modelscan fickling; do require_import "$module"; done
modelscan --version
fickling --version
/usr/local/bin/ctf-os-ai-serialization-smoke
