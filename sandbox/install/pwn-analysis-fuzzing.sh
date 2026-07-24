#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

VALGRIND_DEBIAN_VERSION=1:3.19.0-1

apt_install "valgrind=${VALGRIND_DEBIAN_VERSION}"
pip_install -r /opt/ctf-os/requirements/pwn-fuzzing.txt
# The cached pwn layer imports angr/pyvex as root. Do not bake pyvex's
# process-local /tmp parser cache into the final non-root runtime image.
rm -f /tmp/pyvex_ffi_parser_cache.*

require_command valgrind
require_command boo
require_import boofuzz
valgrind --version | grep -F 'valgrind-3.19.0'
python3 -c 'from importlib.metadata import version; assert version("boofuzz") == "0.4.2"'
