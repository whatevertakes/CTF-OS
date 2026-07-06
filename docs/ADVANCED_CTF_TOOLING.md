# Advanced CTF Tooling Contract

This document is the update contract for the broad CTF tool surface used by
the team winning-mode setup. Team members get this surface through
`tools/setup_workspace.sh team`; `tools/setup_workspace.sh advanced` remains a
compatibility entrypoint for refreshing only the managed advanced tools.

## Install And Patch Path

Run from the repository root:

```bash
. .codex/env.sh
tools/setup_workspace.sh team --branch <github-user>
```

For a no-change preview:

```bash
tools/setup_workspace.sh advanced --dry-run
```

Patch/update contract:

- Re-run `tools/setup_workspace.sh team --branch <github-user>` after pulling
  `main` to refresh the full team environment. Use
  `tools/setup_workspace.sh advanced` only when you intentionally want to
  refresh managed user-local advanced tools without the rest of the team setup.
  Go, npm, cargo, dotnet, pipx, Foundry, Ghidra, and container helpers are
  requested from their latest upstream channel unless an upstream installer
  pins internally.
- Re-run apt updates through the same script from an interactive terminal with
  sudo available. In non-interactive sessions without sudo, apt tools are
  skipped with warnings instead of blocking the setup.
- Keep required external GUI, licensed, Windows-only, hardware-specific,
  service-style, or cloud-provider tools out of Git and record their local
  version in challenge notes when used as solve evidence.
- Never commit cloud credentials, SDR captures with private content, malware
  samples, large third-party binaries, package caches, or third-party
  dependency directories.

## Script-Managed And Required External Surface

Both columns are mandatory team deep profile surfaces. "Script-managed" means
the workspace script can usually install or refresh the tool in a portable
user-local way. "Required external" means the tool is still required by the
team standard, but licensing, GUI, Windows, cloud credentials, service runtime,
platform policy, or non-portable installers keep it outside Git and outside
forced unattended automation. Required external tools must be installed by the
operator and exposed through PATH/version checks.

| Category | Script-managed, team-required | Required external, team-required |
| --- | --- | --- |
| Web | `nuclei`, `katana`, `feroxbuster`, `amass`, `subfinder`, `gau`, `waybackurls`, `hakrawler`, `dalfox`, `commix`, `interactsh-client`, `dnsx`, `naabu`, `httpie` | `XSStrike`, `phpggc` |
| Pwn | `valgrind`, `afl-fuzz`, `honggfuzz`, `radamsa`, `heaptrack`, `pwndbg-gdb`, `patchelf`, qemu profiles | `gef-gdb`, `peda-gdb`, `keystone-as` |
| Reverse engineering | `capa`, `rizin`, `cutter`, `ilspycmd` when `dotnet` is present, `monodis`, `emcc`, `llvm-objdump`, Ghidra wrappers | `dotnet`, `rz-ghidra`, `r2ghidra`, `cfr`, `procyon`, `dnspy` |
| Crypto | `yafu`, `msieve`, `cado-nfs`, `gap`, `fplll`, `pari-gp` | `magma` |
| Forensics/stego | `bulk_extractor`, `zeek`, `outguess`, `exiv2`, `ripgrep-all`, existing binwalk/exiftool/Sleuth Kit/steg tools | `NetworkMiner`, `pdfid`, `pdf-parser`, `oledump` |
| Mobile | `apkid`, `apksigner`, `mobsfscan`, existing `adb`, `objection`, `frida`, `jadx`, `apktool` | full `MobSF` service |
| Malware | `capa`, `yara`, `upx`, Volatility3 | `diec`, `pestudio`, `peid` |
| Cloud/container | `helm`, `k9s`, `kind`, `minikube`, `podman`, `cosign`, `dive`, `regctl`, `oras`, `aws`, `checkov`, `kube-linter`, `kube-score`, plus existing `kubectl`, `trivy`, `syft`, `grype`, `crane`, `skopeo` | `nerdctl`, `terraform`, `terragrunt`, `gcloud`, `az`, `kubescape` |
| AI/ML | `garak`, `promptfoo` | model/API credentials are never installed or stored by this workspace |
| RF/hardware/side-channel | `inspectrum`, `sigmf-cli`, `rtl_433`, `rtl_sdr`, `hackrf_info`, `sigrok-cli`, `pulseview`, `openocd`, `arm-none-eabi-gcc`, `arm-none-eabi-objdump`, `chipwhisperer`, `audacity`, GNU Radio, URH | `baudline` |

The distinction is operational, not optionality. Required external tools are
excluded from unattended installation because they are licensed, GUI-only,
platform-specific, credential-sensitive, hardware-bound, or high-impact
services, but strict deep verification still treats missing commands or failed
version checks as team setup failures.

## Verification

After install or patching, run the relevant strict deep check:

```bash
python3 tools/preflight_check.py --strict-deep --category web
python3 tools/preflight_check.py --strict-deep --category pwn
python3 tools/preflight_check.py --strict-deep --category rev
python3 tools/preflight_check.py --strict-deep --category crypto
python3 tools/preflight_check.py --strict-deep --category forensics
python3 tools/preflight_check.py --strict-deep --category stego
python3 tools/preflight_check.py --strict-deep --category mobile
python3 tools/preflight_check.py --strict-deep --category malware
python3 tools/preflight_check.py --strict-deep --category cloud
python3 tools/preflight_check.py --strict-deep --category container
python3 tools/preflight_check.py --strict-deep --category ai-ml
python3 tools/preflight_check.py --strict-deep --category hardware-rf
python3 tools/preflight_check.py --strict-deep --category side-channel
```

For a compact local inventory:

```bash
tools/version_report.sh
```

Scanner output is not solve proof by itself. Preserve the exact command,
target scope, request/response transcript, sample hash, or local artifact path
that makes a finding reproducible.
