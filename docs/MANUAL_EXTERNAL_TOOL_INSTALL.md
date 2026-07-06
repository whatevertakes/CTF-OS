# Manual External Tool Install Plan

This file tracks team-required external tools that are intentionally outside the
unattended installer. They are not optional for full workstation parity, but
they require operator action because of sudo, licenses, GUI installers,
platform-specific packaging, cloud credentials, service runtimes, or binaries
that should not be committed to this workspace.

Use this with:

```bash
tools/setup_workspace.sh team --strict-external
```

The command above turns missing external tools into failures after the operator
has installed them and exposed their commands on `PATH`.

## Rule

- It is OK to keep install instructions and wrapper scripts in Git.
- Do not commit proprietary installers, downloaded GUI applications, cloud
  credentials, API tokens, license files, or heavyweight service state.
- Prefer user-local wrappers in `.local/bin` or `.codex/bin` that point at real
  external executables.
- `sudo` commands belong in operator-run instructions. Codex should not require
  unattended sudo to pass default team setup.

## Sudo Or System Package Candidates

These can usually be installed with OS package managers or official package
feeds, but the exact commands vary by distro and team policy:

| Category | Tool | Expected command | Notes |
| --- | --- | --- | --- |
| pwn | `keystone-as` | `keystone-as` | Install Keystone assembler from OS/package manager if available. |
| rev | `dotnet` | `dotnet` | Install the Microsoft .NET SDK for the host OS. Enables `ilspycmd`. |
| malware | `diec` | `diec` | Detect It Easy CLI/GUI release or distro package. |
| cloud/container | `terraform` | `terraform` | Install HashiCorp release or approved distro package. Keep provider credentials outside the repo. |
| cloud | `gcloud` | `gcloud` | Install Google Cloud SDK. Keep account config outside the repo. |
| cloud | `az` | `az` | Install Azure CLI. Keep account config outside the repo. |
| cloud/container | `kubescape` | `kubescape` | Install upstream release, package, or approved internal package. |
| cloud/container | `nerdctl` | `nerdctl` | Install a release matching local containerd. |

## User-Local Wrapper Candidates

These do not need committed binaries. Install or clone them outside the repo,
then expose a stable wrapper on `PATH`.

| Category | Tool | Expected command | Wrapper target |
| --- | --- | --- | --- |
| web | `XSStrike` | `xsstrike` | Approved external checkout of `XSStrike/xsstrike.py`. |
| web | `phpggc` | `phpggc` | Approved external checkout of `phpggc`. |
| pwn | `gef-gdb` | `gef-gdb` | Wrapper invoking `gdb` with approved `gef.py`. |
| pwn | `peda-gdb` | `peda-gdb` | Wrapper invoking `gdb` with approved `peda.py`. |
| rev | `cfr` | `cfr` | Wrapper invoking `java -jar` on the CFR jar. |
| rev | `procyon` | `procyon` | Wrapper invoking `java -jar` on Procyon decompiler jars. |
| rev | `rz-ghidra` | `rz-ghidra` | Rizin plugin installed for the local Rizin version. |
| rev | `r2ghidra` | `r2ghidra` | Radare2 plugin installed for the local radare2 version. |
| mobile | `MobSF` | `mobsf` | Local service wrapper or official container launcher. |

## Licensed, GUI, Windows, Or Non-Portable Tools

These should be installed by the operator outside the repo. Only wrappers or
PATH checks belong here.

| Category | Tool | Expected command | Reason |
| --- | --- | --- | --- |
| crypto | `magma` | `magma` | Commercial CAS requiring a valid license. |
| forensics | `NetworkMiner` | `NetworkMiner` | GUI release. |
| malware | `pestudio` | `pestudio` | Windows GUI, external binary. |
| malware | `peid` | `peid` | Legacy Windows GUI/tooling, external binary. |
| rev | `dnspy` | `dnspy` | Windows GUI, use dnSpyEx or approved local copy. |
| hardware-rf/side-channel | `baudline` | `baudline` | Closed-source signal GUI. |

## Moved From Managed After Local Failures

These tools used to be attempted by the unattended advanced installer. They are
still team-required for full workstation parity, but local package, source
build, GUI, dependency, or command-name failures made them too brittle for the
default managed setup. Install them externally, then expose the expected
command on `PATH`.

| Category | Tool label | Expected command | Why external now |
| --- | --- | --- | --- |
| crypto | `yafu` | `yafu` | Local apt/source build path was not reliable enough for unattended setup. |
| crypto | `msieve` | `msieve` | Local apt/source build path was not reliable enough for unattended setup. |
| forensics | `bulk_extractor` | `bulk_extractor` | Package/source build path failed locally and is now operator-managed. |
| pwn | `honggfuzz` | `honggfuzz` | Package/source build path failed locally and is now operator-managed. |
| web | `feroxbuster` | `feroxbuster` | Apt/Cargo managed install path failed locally and is now operator-managed. |
| forensics | `ripgrep-all` | `rga` | Package/Cargo install and command exposure are now operator-managed. |
| rev | `cutter` | `cutter` | GUI/package install path is too brittle for unattended setup. |
| forensics | `zeek` | `zeek` | Default package/feed/source paths failed locally; expose the real Zeek binary after install. |
| forensics | `oledump` | `oledump.py` | Didier Stevens `oledump.py` and its `olefile` dependency are now operator-managed. |
| rev | `rizin` | `rizin` | Source/package build path failed locally and is now operator-managed. |

## Verification

After installing a subset, run:

```bash
tools/preflight_check.py --deep --strict-deep --external-policy report
```

For a parity gate that fails on missing external tools:

```bash
tools/preflight_check.py --deep --strict-deep --external-policy fail
```
