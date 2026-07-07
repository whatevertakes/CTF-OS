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
- Installer phases are best-effort by design. `install_apt_tools || true`,
  `install_go_tools || true`, Cargo, dotnet, and source fallback phases keep
  the setup moving so later phases can still install useful tools. The final
  gate is strict deep preflight: managed gaps fail there, while default
  external/manual gaps are reported separately.
- Keep required external GUI, licensed, Windows-only, hardware-specific,
  service-style, or cloud-provider tools out of Git and record their local
  version in challenge notes when used as solve evidence.
- The default team setup fails only on script-managed deep profile gaps.
  Required external tools are reported separately. Use
  `tools/setup_workspace.sh team --strict-external` for full workstation
  parity where external/manual gaps should fail the setup.
- Never commit cloud credentials, SDR captures with private content, malware
  samples, large third-party binaries, package caches, or third-party
  dependency directories.

## Script-Managed And Required External Surface

Both columns are mandatory team deep profile surfaces. The difference is the
default gate. "Script-managed" means the workspace script can usually install
or refresh the tool in a portable user-local way, so missing or broken managed
tools fail the default team setup. "Required external" means the tool is still
required by the team standard, but licensing, GUI, Windows, cloud credentials,
service runtime, platform policy, or non-portable installers keep it outside
Git and outside forced unattended automation. Required external tools must be
installed by the operator and exposed through PATH/version checks; default
setup reports gaps, while `--strict-external` turns those gaps into failures.
Rows include command checks plus category-specific Python import checks where
the deep profile defines them.

| Category | Script-managed, team-required | Required external, team-required |
| --- | --- | --- |
| Web | `arjun`, `flask-unsign`, `shodan`, `wafw00f`, `sqlmap`, `ffuf`, `gobuster` | `nuclei`, `katana`, `feroxbuster`, `amass`, `subfinder`, `gau`, `waybackurls`, `hakrawler`, `dalfox`, `XSStrike`, `commix`, `phpggc`, `interactsh-client`, `dnsx`, `naabu`, `httpie` |
| Web3 | `forge`, `cast`, `anvil`, `chisel`, `solc`, `slither`, `halmos` | None |
| Pwn | `pwndbg-gdb`, `pwninit`, `patchelf`, `radamsa`, `qemu-x86_64`, `qemu-aarch64`, `qemu-system-x86_64`, `qemu-system-arm`, `qemu-system-aarch64` | `valgrind`, `afl-fuzz`, `honggfuzz`, `gef-gdb`, `peda-gdb`, `heaptrack`, `keystone-as` |
| Reverse engineering | `ghidra-check`, `objdump`, `strings`, `ilspycmd`, `floss`, `yara`, `upx`, `qemu-x86_64`, `qemu-aarch64`, `qemu-system-x86_64`, `qemu-system-arm`, `qemu-system-aarch64` | `capa`, `rizin`, `cutter`, `rz-ghidra`, `r2ghidra`, `cfr`, `procyon`, `dotnet`, `dnspy`, `monodis`, `emcc`, `llvm-objdump` |
| Crypto | `RsaCtfTool`, `z3`, `fplll`, `pari-gp`, `cado-nfs`; Python modules: `z3-solver`, `fpylll` | `yafu`, `msieve`, `gap`, `magma` |
| Forensics | `binwalk`, `exiftool`, `foremost`, `mmls`, `pdfid.py`, `pdf-parser.py`, `floss`, `stegolsb`, `zsteg`, `yara`, `upx`, `fls`, `vol`; Python modules: `yara-python`, `volatility3` | `bulk_extractor`, `zeek`, `NetworkMiner`, `oledump`, `outguess`, `exiv2`, `ripgrep-all` |
| Stego | `exiftool`, `binwalk`, `steghide`, `stegseek`, `stegolsb`, `zsteg` | `outguess` |
| Mobile | `jadx`, `apktool`, `adb`, `objection`, `frida`, `frida-ps` | `apkid`, `apksigner`, `MobSF`, `mobsfscan` |
| Malware | `yara`, `upx`, `vol`; Python modules: `yara-python`, `volatility3` | `capa`, `diec`, `pestudio`, `peid` |
| Cloud | `kubectl`, `minikube`, `trivy`, `syft`, `grype`, `crane`, `terragrunt`, `skopeo` | `helm`, `k9s`, `kind`, `podman`, `nerdctl`, `cosign`, `dive`, `regctl`, `oras`, `aws`, `gcloud`, `az`, `terraform`, `checkov`, `kube-linter`, `kube-score`, `kubescape` |
| Container | `kubectl`, `minikube`, `trivy`, `syft`, `grype`, `crane`, `terragrunt`, `skopeo` | `helm`, `k9s`, `kind`, `podman`, `nerdctl`, `cosign`, `dive`, `regctl`, `oras`, `terraform`, `checkov`, `kube-linter`, `kube-score`, `kubescape` |
| AI/ML | `garak` | `promptfoo` |
| Hardware/RF | `gnuradio-config-info`, `urh`, `sigmf_validate`; Python modules: `chipwhisperer`, `sigmf` | `inspectrum`, `rtl_433`, `rtl_sdr`, `hackrf_info`, `sigrok-cli`, `pulseview`, `openocd`, `arm-none-eabi-gcc`, `arm-none-eabi-objdump`, `audacity`, `baudline` |
| Side-channel | `gnuradio-config-info`, `sigmf_validate`; Python modules: `chipwhisperer`, `sigmf` | `openocd`, `arm-none-eabi-gcc`, `arm-none-eabi-objdump`, `audacity`, `baudline` |
| Misc | `qemu-x86_64`, `qemu-aarch64`, `qemu-system-x86_64`, `qemu-system-arm`, `qemu-system-aarch64` | None |
| Programming | `z3`; Python module: `z3-solver` | None |

The distinction is operational, not optionality. Required external tools are
excluded from unattended installation because they are licensed, GUI-only,
platform-specific, credential-sensitive, hardware-bound, or high-impact
services. Default strict deep verification prints `EXTERNAL ...` report lines
and summary counts for those tools without failing the setup. Full parity
checks use `--external-policy fail` or the team setup `--strict-external`
option.

Operator-run install notes for those tools are tracked in
`docs/MANUAL_EXTERNAL_TOOL_INSTALL.md`, and the short terminal checklist is
available as `tools/manual_external_tool_plan.sh`. Sudo-requiring tools can be
documented there; they are only excluded from unattended Codex execution.

## Install Failure Model

If `sudo -n true` returns `sudo: a password is required`, Codex or another
non-interactive session cannot run the apt phase. Managed apt-targeted tools
such as `radamsa`, `cado-nfs`, and `minikube` may then remain missing unless a
Go, upstream binary, or source fallback succeeds.

Some apt package names also have no candidate in a default distro repository.
For example, a package with `Candidate: (none)` will not install through the
default apt phase even when sudo is available. Those cases either use a
configured user-local fallback or remain as managed preflight failures until
the installer gains a reliable fallback. Tools moved to the required external
column after local failures are intentionally outside this managed failure
model and produce `EXTERNAL ...` report lines by default.

The installer never creates fake passing commands. Wrappers and symlinks are
created only when they point at a real executable or a real checked-out script.

## Verification

After install or patching, run the relevant strict deep check:

```bash
python3 tools/preflight_check.py --strict-deep --category web
python3 tools/preflight_check.py --strict-deep --category web3
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
python3 tools/preflight_check.py --strict-deep --category misc
python3 tools/preflight_check.py --strict-deep --category programming
```

For full workstation parity, include external/manual tools in the failure gate:

```bash
python3 tools/preflight_check.py --strict-deep --external-policy fail --category rev
tools/setup_workspace.sh team --branch <github-user> --strict-external
```

For a compact local inventory:

```bash
tools/version_report.sh
```

Scanner output is not solve proof by itself. Preserve the exact command,
target scope, request/response transcript, sample hash, or local artifact path
that makes a finding reproducible.
