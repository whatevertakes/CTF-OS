# Advanced CTF Tooling Contract

This document is the update contract for the broad, non-default CTF tool
surface. The default workspace remains lean; these tools are installed only
when an operator explicitly opts in with `tools/setup_workspace.sh advanced`
or when a challenge notes file records a specific need.

## Install And Patch Path

Run from the repository root:

```bash
. .codex/env.sh
tools/setup_workspace.sh advanced
```

For a no-change preview:

```bash
tools/setup_workspace.sh advanced --dry-run
```

Patch/update contract:

- Re-run `tools/setup_workspace.sh advanced` to refresh managed user-local
  tools. Go, npm, cargo, dotnet, pipx, Foundry, Ghidra, and container helpers
  are requested from their latest upstream channel unless an upstream installer
  pins internally.
- Re-run apt updates through the same script from an interactive terminal with
  sudo available. In non-interactive sessions without sudo, apt tools are
  skipped with warnings instead of blocking the setup.
- Keep manually managed GUI, licensed, Windows-only, hardware-specific, or
  cloud-provider tools out of Git and record their local version in challenge
  notes when used as solve evidence.
- Never commit cloud credentials, SDR captures with private content, malware
  samples, package caches, or third-party dependency directories.

## Managed Tool Surface

| Category | Managed by script | Manual or external |
| --- | --- | --- |
| Web | `nuclei`, `katana`, `feroxbuster`, `amass`, `subfinder`, `gau`, `waybackurls`, `hakrawler`, `dalfox`, `commix`, `interactsh-client`, `dnsx`, `naabu`, `httpie` | `XSStrike`, `phpggc` |
| Pwn | `valgrind`, `afl-fuzz`, `honggfuzz`, `radamsa`, `heaptrack`, `pwndbg-gdb`, `patchelf`, qemu profiles | `gef`, `peda`, `keystone-as` when unavailable from the OS package set |
| Reverse engineering | `capa`, `rizin`, `cutter`, `ilspycmd` when `dotnet` is present, `monodis`, `emcc`, `llvm-objdump`, Ghidra wrappers | `dotnet`, `rz-ghidra`, `r2ghidra`, `cfr`, `procyon`, `dnspy` |
| Crypto | `yafu`, `msieve`, `cado-nfs`, `gap`, `fplll`, `pari-gp` | `magma` |
| Forensics/stego | `bulk_extractor`, `zeek`, `outguess`, `exiv2`, `ripgrep-all`, existing binwalk/exiftool/Sleuth Kit/steg tools | `NetworkMiner`, `pdfid`, `pdf-parser`, `oledump` |
| Mobile | `apkid`, `apksigner`, `mobsfscan`, existing `adb`, `objection`, `frida`, `jadx`, `apktool` | full `MobSF` service |
| Malware | `capa`, `yara`, `upx`, Volatility3 | `diec`, `pestudio`, `peid` |
| Cloud/container | `helm`, `k9s`, `kind`, `minikube`, `podman`, `cosign`, `dive`, `regctl`, `oras`, `aws`, `terragrunt`, `checkov`, `kube-linter`, `kube-score`, plus existing `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo` | `nerdctl`, `terraform`, `gcloud`, `az`, `kubescape` when not available through local package policy |
| AI/ML | `garak`, `promptfoo` | model/API credentials are never installed or stored by this workspace |
| RF/hardware/side-channel | `inspectrum`, `sigmf-cli`, `rtl_433`, `rtl_sdr`, `hackrf_info`, `sigrok-cli`, `pulseview`, `openocd`, `arm-none-eabi-gcc`, `arm-none-eabi-objdump`, `chipwhisperer`, `audacity`, GNU Radio, URH | `baudline` |

The distinction is operational, not a claim that a manual tool is less useful.
Manual tools are excluded from unattended installation because they are
licensed, GUI-only, platform-specific, hardware-bound, or high-impact services.

## Verification

After install or patching, run the relevant deep check:

```bash
python3 tools/preflight_check.py --deep --category web
python3 tools/preflight_check.py --deep --category pwn
python3 tools/preflight_check.py --deep --category rev
python3 tools/preflight_check.py --deep --category crypto
python3 tools/preflight_check.py --deep --category forensics
python3 tools/preflight_check.py --deep --category stego
python3 tools/preflight_check.py --deep --category mobile
python3 tools/preflight_check.py --deep --category malware
python3 tools/preflight_check.py --deep --category cloud
python3 tools/preflight_check.py --deep --category container
python3 tools/preflight_check.py --deep --category ai-ml
python3 tools/preflight_check.py --deep --category hardware-rf
python3 tools/preflight_check.py --deep --category side-channel
```

For a compact local inventory:

```bash
tools/version_report.sh
```

Scanner output is not solve proof by itself. Preserve the exact command,
target scope, request/response transcript, sample hash, or local artifact path
that makes a finding reproducible.
