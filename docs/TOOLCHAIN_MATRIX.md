# Toolchain Matrix

This matrix records dependency expectations for CTF challenge triage and
benchmark evaluation. Strict preflight checks the shared team parity CLI
surface; deep category checks add heavier or target-specific tools.

| Category | Required Tools | Optional Tools |
| --- | --- | --- |
| `mcp-cli` | `mcp`, `fastmcp`, `mcp-proxy`, `mcp-reverse-proxy` | CLI utility surface only; registered MCP servers remain `angr`, `playwright`, `radare2`. |
| `pwn` | `gcc`, `gdb`, `python3`, `pwntools`, `checksec`, `ROPgadget`, `ropper`, `pwninit` | `pwndbg-gdb`, `one_gadget`, `seccomp-tools`, `patchelf`, qemu profiles, `valgrind`, `afl-fuzz`, `honggfuzz`, `radamsa`, `gef`, `peda`, `heaptrack`, `keystone-as`. |
| `rev` | `file`, `strings`, `objdump`, `r2`, `angr`, `floss` | `ghidra`, `ghidra-analyzeHeadless`, `capa`, `rizin`, `cutter`, `rz-ghidra`, `r2ghidra`, `cfr`, `procyon`, `dotnet`, `ilspycmd`, `dnspy`, `monodis`, `emcc`, `llvm-objdump`, `yara`, `upx`, qemu profiles. |
| `web` | `curl`, `python3`, `node`, `playwright`, `arjun`, `flask-unsign`, `wafw00f`, `shodan`, `sqlmap` | `nuclei`, `katana`, `feroxbuster`, `amass`, `subfinder`, `gau`, `waybackurls`, `hakrawler`, `dalfox`, `XSStrike`, `commix`, `phpggc`, `interactsh-client`, `dnsx`, `naabu`, `httpie`, `ffuf`, `gobuster`, Burp/Caido as external GUI tools. |
| `crypto` | `python3`, `RsaCtfTool` | `sage`, `z3`, `fplll`, `pari-gp`, `yafu`, `msieve`, `cado-nfs`, `gap`, `magma` when licensed. |
| `forensics` | `binwalk`, `exiftool`, `tshark`, `floss`, `stegolsb`, `zsteg` | `bulk_extractor`, `zeek`, NetworkMiner, `pdfid`, `pdf-parser`, `oledump`, `foremost`, `sleuthkit` (`fls`, `mmls`), `volatility3`, `outguess`, `exiv2`, `ripgrep-all`, `yara`, `upx`. |
| `stego` | `file`, `exiftool`, `zsteg`, `stegolsb` | `binwalk`, `steghide`, `stegseek`, `outguess`, custom extractors. |
| `mobile` | `jadx`, `apktool`, `frida`, `frida-ps` | `adb`, `objection`, `apkid`, `apksigner`, MobSF, `mobsfscan`, device/emulator-specific tooling. |
| `web3` | `python3`, `forge`, `cast`, `anvil`, `slither` | `chisel`, `solc`, `halmos`, `echidna` when specifically required. |
| `cloud` | `python3`, `jq`, local config parsers | `helm`, `k9s`, `kind`, `minikube`, `kubectl`, `podman`, `nerdctl`, `cosign`, `dive`, `regctl`, `oras`, provider CLIs, `terraform`, `terragrunt`, `checkov`, `trivy`, `syft`, `grype`, `crane`, `skopeo`, Kubernetes scanners inside owned scope. |
| `container/k8s` | `docker`, `tar`, `jq` | `helm`, `k9s`, `kind`, `minikube`, `kubectl`, `podman`, `nerdctl`, `cosign`, `dive`, `regctl`, `oras`, `terraform`, `terragrunt`, `checkov`, `trivy`, `syft`, `grype`, `crane`, `skopeo`, `kube-linter`, `kube-score`, `kubescape`, namespace/capability helpers. |
| `firmware/hardware-rf/avr` | `avr-gcc`, `avr-objdump`, `avr-objcopy`, `avr-size` | `avrdude`, `simavr` |
| `ai-ml` | `python3`, challenge-local scripts | `garak` and `promptfoo` for scoped model behavior probes. |
| `hardware-rf/side-channel` | `python3`, raw captures/traces | `gnuradio`, `urh`, `inspectrum`, `sigmf-cli`, `rtl_433`, `rtl_sdr`, `hackrf_info`, `sigrok-cli`, `pulseview`, `openocd`, `arm-none-eabi-gcc`, `arm-none-eabi-objdump`, ChipWhisperer, `audacity`, `baudline` when specifically required. |

`mcp-reverse-proxy` is maintained as a compatibility CLI wrapper over
`mcp-proxy`. It is not a separate Codex MCP server registration.

`RsaCtfTool` is installed in an isolated user-level venv by
`tools/setup_workspace.sh bootstrap` because its upstream dependency pins can downgrade
general-purpose Python packages. `pwninit` uses the upstream release binary; the
legacy PyPI package is not Python 3 compatible.

Large advanced tools are installed only on demand with
`tools/setup_workspace.sh advanced`; see
`docs/ADVANCED_CTF_TOOLING.md` for the install and patch contract. They are
intentionally excluded from the default team bootstrap because Ghidra,
garak/PyTorch, GNU Radio, GUI tools, and cloud/mobile services add large local
dependencies and can require external credentials, hardware, or licenses.

Corpus entries may record dependency state with:

- `required_tools`: tool names required for the benchmark case.
- `missing_tools`: known missing tools at the time of evaluation.
- `dependency_status`: one of `ok`, `missing`, or `unknown`.

Tool routing observability is separate from dependency health. Use
`docs/TOOL_ROUTING_POLICY.md` for `primary_tools_used`, `tools_considered`,
`tools_used`, `tools_skipped`, and `tool_routing_gap` semantics.
