#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Manual external tool plan
=========================

These tools are team-required for full workstation parity, but they are not
installed by the unattended setup script. Install them outside this repository,
then expose the expected command on PATH.

Moved from managed after local failures:
  crypto:
    yafu               expected command: yafu
    msieve             expected command: msieve
  forensics:
    bulk_extractor     expected command: bulk_extractor
    zeek               expected command: zeek
    oledump            expected command: oledump.py
    ripgrep-all        expected command: rga
  pwn:
    honggfuzz          expected command: honggfuzz
  rev:
    rizin              expected command: rizin
    cutter             expected command: cutter
  web:
    feroxbuster        expected command: feroxbuster

Sudo/system-package candidates:
  pwn:
    keystone-as        expected command: keystone-as
  rev:
    dotnet             expected command: dotnet
  malware:
    diec               expected command: diec
  cloud/container:
    nerdctl            expected command: nerdctl
    terraform          expected command: terraform
    kubescape          expected command: kubescape
  cloud:
    gcloud             expected command: gcloud
    az                 expected command: az

User-local wrapper candidates:
  web:
    XSStrike           expected command: xsstrike
    phpggc             expected command: phpggc
  pwn:
    gef-gdb            expected command: gef-gdb
    peda-gdb           expected command: peda-gdb
  rev:
    rz-ghidra          expected command: rz-ghidra
    r2ghidra           expected command: r2ghidra
    cfr                expected command: cfr
    procyon            expected command: procyon
  mobile:
    MobSF              expected command: mobsf

Licensed/GUI/non-portable:
  crypto:
    magma              expected command: magma
  forensics:
    NetworkMiner       expected command: NetworkMiner
  malware:
    pestudio           expected command: pestudio
    peid               expected command: peid
  rev:
    dnspy              expected command: dnspy
  hardware-rf:
    baudline           expected command: baudline
  side-channel:
    baudline           expected command: baudline

Policy:
  - Put instructions and wrappers in Git.
  - Do not put proprietary installers, cloud credentials, license files, or
    service state in Git.
  - Wrappers must point at real external executables; do not create fake passing
    commands.

Verification:
  python3 tools/preflight_check.py --strict-deep --external-policy report --category web
  tools/setup_workspace.sh team --strict-external

More detail:
  docs/MANUAL_EXTERNAL_TOOL_INSTALL.md
EOF
