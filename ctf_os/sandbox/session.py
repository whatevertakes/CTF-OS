"""Bounded persistent shell, remote, and debugger sessions inside one lane."""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..blackboard import output_hash
from ..workspace import atomic_json, atomic_text
from .runtime import (
    SandboxError,
    controller_exec_prefix,
    firewall_packets,
    target_observation,
    user_exec_prefix,
)

SESSION_KINDS = frozenset({"shell", "remote", "debugger"})
MAX_READ = 64 * 1024
# A verified flag is at most this long, so carrying this many trailing bytes of
# the previous durable read output is enough to detect a flag that straddles two
# session-read receipts without re-emitting already-returned output.
MAX_FLAG_TAIL = 1024
# The root-owned in-container monitor refreshes the heartbeat every 2s while the
# session process is alive; 30s of silence means the process or monitor is gone.
SESSION_HEARTBEAT_STALE_SECONDS = 30
_SESSION_ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,47}\Z")
_CONTROLLER_DIR = re.compile(r"/tmp/\.ctf-os-controller-[0-9a-f]{32}\Z")
_CONTROLLER_CLEANUP_SCRIPT = (
    "c=$1; w=$2; "
    "kill_exact() { f=$1; group=$2; "
    "read p st <\"$c/$f\" 2>/dev/null || return 0; "
    "cur=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
    "print(s[s.rfind(\") \")+2:].split()[19])' \"$p\" 2>/dev/null || true); "
    "[ \"$cur\" = \"$st\" ] || return 0; "
    "if [ \"$group\" = yes ]; then kill -TERM \"-$p\" 2>/dev/null || true; "
    "else kill -TERM \"$p\" 2>/dev/null || true; fi; }; "
    "if [ -d \"$c\" ] && [ ! -L \"$c\" ]; then "
    "kill_exact identity yes; kill_exact keeper no; kill_exact monitor no; fi; "
    "rm -rf -- \"$c\"; "
    "setpriv --reuid=1001 --regid=1001 --clear-groups rm -rf -- \"$w\""
)

_TOOLS: dict[str, tuple[str, ...]] = {
    "base": (
        "bash", "python3", "rg", "file", "strings", "xxd", "curl", "wget",
        "git", "jq", "nc", "socat", "objdump", "readelf", "nm", "nmap",
        "gcc", "g++", "cmake", "clang", "ruby", "java",
    ),
    "pwn": (
        "gdb", "pwndbg", "checksec", "pwninit", "angrop", "seccomp-tools",
        "gdb-multiarch", "ctf-ghidra-headless", "capa", "frida", "frida-ps",
        "strace", "ltrace", "patchelf", "ROPgadget", "ropper", "one_gadget",
        "musl-gcc", "cpio", "valgrind", "afl-fuzz", "afl-showmap",
        "afl-cmin", "afl-tmin", "afl-clang-fast", "afl-clang-fast++",
        "afl-qemu-trace", "boo", "atheris", "cargo", "rustc", "cargo-fuzz",
        "qemu-x86_64", "qemu-i386", "qemu-aarch64",
        "qemu-arm", "qemu-mips", "qemu-mipsel", "qemu-riscv64",
        "qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-arm",
        "qemu-system-riscv32", "qemu-system-riscv64", "qemu-img",
    ),
    "web": (
        "httpx", "nuclei", "ctf-nuclei-scan", "semgrep", "sqlmap", "ffuf",
        "sstimap", "dalfox", "schemathesis", "chromium", "chromedriver",
        "node", "npm", "php", "sqlite3", "redis-cli", "psql", "mysql",
    ),
    "rev": (
        "gdb", "gdb-multiarch", "ctf-ghidra-headless", "analyzeHeadless",
        "capa", "r2", "jadx", "jadx-gui", "apktool", "frida", "frida-ps",
        "upx", "wasm-objdump", "wasm2wat", "wasmtime", "javac",
        "mono", "jazzer", "qemu-x86_64", "qemu-i386", "qemu-aarch64",
        "qemu-arm", "qemu-mips", "qemu-mipsel", "qemu-riscv64",
        "qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-arm",
        "qemu-system-riscv32", "qemu-system-riscv64", "qemu-img",
    ),
    "crypto": (
        "sage", "openssl", "z3", "ares", "RsaCtfTool", "cado-nfs",
        "hashcat", "gp", "gap", "maxima",
    ),
    "forensic": (
        "binwalk", "exiftool", "tshark", "tcpdump", "vol", "mmls", "fls",
        "icat", "foremost", "testdisk", "photorec", "dcfldd", "steghide",
        "stegseek", "zsteg", "convert", "tesseract", "pngcheck", "ffmpeg",
        "sox",
    ),
    "misc": (
        "ffmpeg", "sox", "convert", "tesseract", "tshark", "binwalk",
        "exiftool", "dot", "parallel", "podman", "zbarimg", "barcode",
        "php", "lua", "perl", "node", "npm", "ares",
    ),
    "osint": (
        "whois", "dig", "nslookup", "host", "traceroute", "chromium",
        "convert", "tesseract", "exiftool", "ffmpeg", "yt-dlp", "git-lfs",
        "pdftotext", "waybackurls", "sherlock", "maigret", "holehe",
        "theHarvester",
    ),
    "ai": (
        "onnxruntime", "safetensors", "pickletools", "protoc", "h5dump",
        "ncdump", "dot", "jupyter", "modelscan", "fickling",
    ),
    "cloud": (
        "aws", "az", "gcloud", "kubectl", "helm", "terraform", "tofu",
        "podman", "skopeo", "oras", "cosign", "trivy", "syft", "grype",
        "kustomize", "opa", "conftest", "checkov", "semgrep", "yq",
    ),
}
_HELP = {
    "ctf-ghidra-headless": "ctf-ghidra-headless INPUT [TIMEOUT_SECONDS] exports bounded decompilation.",
    "analyzeHeadless": "Prefer ctf-ghidra-headless so projects remain bounded below /work and output goes to /artifacts.",
    "nuclei": "Prefer ctf-nuclei-scan with the bundled offline challenge templates.",
    "ctf-nuclei-scan": "Run ctf-nuclei-scan TARGET TEMPLATE [OUTPUT_NAME.jsonl] only against a declared HTTP(S) target.",
    "gdb": "Use gdb in a persistent debugger session for interactive breakpoints and memory inspection.",
    "gdb-multiarch": "Use gdb-multiarch in a persistent debugger session for foreign-architecture binaries.",
    "pwndbg": "Run `pwndbg -q BINARY` in a persistent debugger session for enhanced GDB analysis.",
    "angrop": "Import angrop from Python to generate ROP chains for an angr project.",
    "vol": "Run Volatility 3 as `vol`; use `vol --help` to list framework options.",
    "onnxruntime": "Import onnxruntime from Python; it is a library, not a standalone command.",
    "safetensors": "Import safetensors from Python; it is a library, not a standalone command.",
    "pickletools": "Run the standard-library disassembler as `python3 -m pickletools`.",
    "nc": "Use `nc -h` for usage; connect only to an organizer-declared host and port.",
    "socat": "Use `socat -h` for usage; connect only to an organizer-declared endpoint.",
    "ares": "Use Ares for automatic decoding; keep generated output below /artifacts.",
    "sstimap": "Run SSTImap only against an organizer-declared HTTP(S) target.",
    "holehe": "Holehe performs an online update check at startup and requires declared egress.",
    "sherlock": "Run Sherlock only for public, challenge-scoped usernames and declared egress.",
    "maigret": "Run Maigret only for public, challenge-scoped usernames and declared egress.",
    "theHarvester": "Run theHarvester only against public challenge domains and declared egress.",
    "afl-fuzz": "Run AFL++ as `afl-fuzz -i CORPUS -o FINDINGS -- TARGET`; keep corpora and findings below /work or /artifacts.",
    "afl-showmap": "Use `afl-showmap -o MAP -- TARGET` for one bounded coverage-map probe.",
    "afl-cmin": "Use `afl-cmin -i CORPUS -o MINIMIZED -- TARGET` to minimize an AFL++ corpus.",
    "afl-tmin": "Use `afl-tmin -i TESTCASE -o MINIMIZED -- TARGET` to minimize one AFL++ testcase.",
    "afl-qemu-trace": "Use through AFL++ QEMU mode (`afl-fuzz -Q` or `afl-showmap -Q`), not as a general system emulator.",
    "boo": "Boofuzz installs the real `boo` CLI; import `boofuzz` in a Python harness for protocol fuzzing.",
    "atheris": "Atheris is a Python library: write a TestOneInput callback, then run the harness with bounded libFuzzer flags such as `-runs=100`.",
    "cargo-fuzz": "Run the installed binary as `cargo fuzz`; the pinned nightly toolchain and an offline libfuzzer-sys cache are preinstalled.",
    "afl-clang-fast": "Compile a local target with AFL++ instrumentation before running afl-fuzz.",
    "afl-clang-fast++": "Compile a local C++ target with AFL++ instrumentation before running afl-fuzz.",
    "valgrind": "Use `valgrind --tool=memcheck --leak-check=full TARGET` for bounded dynamic memory analysis.",
    "schemathesis": "Run `schemathesis run SCHEMA` against a declared API target; use `--max-examples` or `--max-time` to bound a probe.",
    "jazzer": "Compile a Java fuzz target with `/opt/jazzer/jazzer_standalone.jar`, then run `jazzer --cp=CLASSPATH --target_class=CLASS -runs=N`.",
    "chromium": "Use `/usr/bin/chromium --headless --no-sandbox` or Playwright's system Chromium integration inside the sandbox.",
    "chromedriver": "Use `/usr/bin/chromedriver` with the matching Debian Chromium build.",
    "qemu-aarch64": "Run AArch64 Linux user-mode binaries with the `/usr/aarch64-linux-gnu` sysroot when dynamically linked.",
    "qemu-arm": "Run ARM Linux user-mode binaries with the `/usr/arm-linux-gnueabihf` sysroot when dynamically linked.",
    "qemu-mipsel": "Run MIPSEL Linux user-mode binaries with the `/usr/mipsel-linux-gnu` sysroot when dynamically linked.",
    "qemu-riscv64": "Run RISC-V 64 Linux user-mode binaries with the `/usr/riscv64-linux-gnu` sysroot when dynamically linked.",
    "wasm-objdump": "Use WABT's `wasm-objdump` to inspect WebAssembly sections and disassembly.",
    "wasm2wat": "Use WABT's `wasm2wat` to convert a WebAssembly module to text.",
    "RsaCtfTool": "Run RsaCtfTool with challenge-provided RSA parameters or keys and keep outputs below /work or /artifacts.",
    "cado-nfs": "Use cado-nfs only for a bounded factorization candidate after cheaper RSA attacks fail.",
    "hashcat": "Use hashcat with a bounded mask or wordlist; GPU is used only when the sandbox received verified GPU access.",
    "mmls": "Use mmls to enumerate disk-image partitions before fls or icat.",
    "fls": "Use fls on an identified filesystem offset to enumerate deleted and live entries.",
    "icat": "Use icat to extract one inode from a challenge disk image into /artifacts.",
    "zsteg": "Use zsteg for bounded PNG/BMP steganography analysis.",
    "waybackurls": "Run waybackurls only for a public challenge domain allowed by the race target policy.",
    "modelscan": "Run modelscan before loading pickle, joblib, PyTorch, H5, or SavedModel artifacts.",
    "fickling": "Use fickling to statically inspect or safely analyze pickle bytecode before any load.",
}
_VERSION_COMMANDS: dict[str, tuple[str, ...]] = {
    "java": ("java", "--version"),
    "javac": ("javac", "--version"),
    "nc": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "netcat-openbsd",
    ),
    "socat": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "socat",
    ),
    "angrop": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('angrop'))",
    ),
    "checksec": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('pwntools'))",
    ),
    "pwndbg": (
        "pwndbg", "--batch", "-q", "-ex",
        "pi import pwndbg; print(pwndbg.__version__)", "-ex", "quit",
    ),
    "ctf-nuclei-scan": (
        "sh", "-ec",
        "command -v ctf-nuclei-scan >/dev/null; grep '^nuclei=' /opt/ctf-os/tool-versions.lock",
    ),
    "httpx": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('httpx'))",
    ),
    "semgrep": (
        "sh", "-ec",
        "command -v semgrep >/dev/null; grep '^semgrep=' /opt/ctf-os/tool-versions.lock",
    ),
    "ffuf": ("ffuf", "-V"),
    "ctf-ghidra-headless": (
        "sh", "-ec",
        "grep '^ghidra=' /opt/ctf-os/tool-versions.lock",
    ),
    "analyzeHeadless": (
        "sh", "-ec",
        "command -v analyzeHeadless >/dev/null; grep '^ghidra=' /opt/ctf-os/tool-versions.lock",
    ),
    "jadx-gui": (
        "sh", "-ec",
        "command -v jadx-gui >/dev/null; grep '^jadx=' /opt/ctf-os/tool-versions.lock",
    ),
    "frida-ps": (
        "sh", "-ec",
        "command -v frida-ps >/dev/null; grep '^frida_tools=' /opt/ctf-os/tool-versions.lock",
    ),
    "openssl": ("openssl", "version"),
    "binwalk": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('binwalk'))",
    ),
    "vol": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('volatility3'))",
    ),
    "foremost": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "foremost",
    ),
    "ffmpeg": ("ffmpeg", "-version"),
    "dig": ("dig", "-v"),
    "onnxruntime": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('onnxruntime-gpu'))",
    ),
    "safetensors": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('safetensors'))",
    ),
    "pickletools": (
        "python3", "-c",
        "import platform; print(f'Python {platform.python_version()} stdlib pickletools')",
    ),
    "kubectl": ("kubectl", "version", "--client=true"),
    "helm": ("helm", "version", "--short"),
    "opa": ("opa", "version"),
    "ares": (
        "sh", "-ec",
        "ares --help >/dev/null; grep '^ares=' /opt/ctf-os/tool-versions.lock",
    ),
    "holehe": (
        "/opt/holehe-venv/bin/python", "-c",
        "from importlib.metadata import version; print(version('holehe'))",
    ),
    "theHarvester": (
        "/opt/theharvester-venv/bin/python", "-c",
        "from importlib.metadata import version; print(version('theHarvester'))",
    ),
    "afl-fuzz": (
        "sh", "-ec",
        "command -v afl-fuzz >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-showmap": (
        "sh", "-ec",
        "command -v afl-showmap >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-cmin": (
        "sh", "-ec",
        "command -v afl-cmin >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-tmin": (
        "sh", "-ec",
        "command -v afl-tmin >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-qemu-trace": (
        "sh", "-ec",
        "command -v afl-qemu-trace >/dev/null; grep '^qemuafl_commit=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-clang-fast": (
        "sh", "-ec",
        "command -v afl-clang-fast >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "afl-clang-fast++": (
        "sh", "-ec",
        "command -v afl-clang-fast++ >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
    ),
    "boo": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('boofuzz'))",
    ),
    "ropper": (
        "sh", "-ec",
        "command -v ropper >/dev/null; python3 -c \"from importlib.metadata import version; print(version('ropper'))\"",
    ),
    "atheris": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('atheris'))",
    ),
    "cargo-fuzz": ("cargo-fuzz", "--version"),
    "RsaCtfTool": (
        "sh", "-ec",
        "command -v RsaCtfTool >/dev/null; grep '^RsaCtfTool=' /opt/ctf-os/tool-versions.lock",
    ),
    "cado-nfs": (
        "sh", "-ec",
        "command -v cado-nfs >/dev/null; grep '^cado-nfs=' /opt/ctf-os/tool-versions.lock",
    ),
    "gap": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "gap-core",
    ),
    "mmls": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "sleuthkit",
    ),
    "fls": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "sleuthkit",
    ),
    "icat": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "sleuthkit",
    ),
    "tcpdump": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "tcpdump",
    ),
    "testdisk": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "testdisk",
    ),
    "photorec": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "testdisk",
    ),
    "dcfldd": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "dcfldd",
    ),
    "steghide": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "steghide",
    ),
    "zsteg": (
        "sh", "-ec",
        "command -v zsteg >/dev/null; grep '^zsteg=' /opt/ctf-os/tool-versions.lock",
    ),
    "convert": ("convert", "-version"),
    "tesseract": ("tesseract", "--version"),
    "pngcheck": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "pngcheck",
    ),
    "sox": ("sox", "--version"),
    "dot": ("dot", "-V"),
    "barcode": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "barcode",
    ),
    "php": ("php", "--version"),
    "lua": ("lua", "-v"),
    "perl": ("perl", "-v"),
    "nslookup": ("dig", "-v"),
    "host": ("dig", "-v"),
    "chromium": ("chromium", "--version"),
    "git-lfs": ("git-lfs", "--version"),
    "pdftotext": ("pdftotext", "-v"),
    "waybackurls": (
        "sh", "-ec",
        "command -v waybackurls >/dev/null; grep '^waybackurls=' /opt/ctf-os/tool-versions.lock",
    ),
    "protoc": ("protoc", "--version"),
    "h5dump": ("h5dump", "-V"),
    "ncdump": (
        "dpkg-query", "--show", "--showformat=${Version}\n", "netcdf-bin",
    ),
    "jupyter": ("jupyter", "--version"),
    "modelscan": ("modelscan", "--version"),
    "fickling": ("fickling", "--version"),
    "schemathesis": ("schemathesis", "--version"),
    "az": ("az", "version"),
    "gcloud": ("gcloud", "version"),
    "aws": ("aws", "--version"),
    "terraform": ("terraform", "version"),
    "tofu": ("tofu", "version"),
    "oras": ("oras", "version"),
    "cosign": ("cosign", "version"),
    "syft": ("syft", "version"),
    "grype": ("grype", "version"),
    "kustomize": ("kustomize", "version"),
    "checkov": ("checkov", "--version"),
}


class SessionError(ValueError):
    pass


def open_session(
    metadata: Mapping[str, Any],
    *,
    session_id: str,
    kind: str,
    command: Sequence[str] | None = None,
    target_identity: str | None = None,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    _validate_session_id(session_id)
    if kind not in SESSION_KINDS:
        raise SessionError("session kind must be shell, remote, or debugger")
    category = str(metadata.get("category"))
    if kind == "debugger" and category not in {"pwn", "rev"}:
        raise SessionError("persistent debugger sessions are exposed only for pwn/rev")
    identities = [str(value) for value in metadata.get("target_identities", [])]
    if kind == "remote":
        if not identities:
            raise SessionError("remote sessions require a declared target or service endpoint")
        if target_identity not in identities:
            raise SessionError("remote session target identity was not declared")
    elif target_identity is not None:
        raise SessionError("target identity is valid only for a remote session")
    argv = list(command or (["bash", "--noprofile", "--norc", "-i"] if kind == "shell" else []))
    if not argv or any(not value or "\x00" in value for value in argv):
        raise SessionError("persistent session requires a non-empty NUL-free argv")
    if kind == "debugger" and Path(argv[0]).name not in {"gdb", "lldb", "pwndbg"}:
        raise SessionError("debugger session command must start with gdb, lldb, or pwndbg")
    lane_root = Path(str(metadata["lane_root"])).resolve()
    state_path = _state_path(lane_root, session_id)
    if state_path.exists() or state_path.is_symlink():
        raise SessionError("persistent session id already exists")
    container_dir = f"/work/.ctf-sessions/{session_id}"
    controller_dir = f"/tmp/.ctf-os-controller-{uuid.uuid4().hex}"
    observed_identity = target_identity or f"challenge:{metadata['challenge_id']}"
    packets_before = firewall_packets(metadata, observed_identity, docker=docker)
    # The target process runs as uid 1001, but the monitor and identity files live
    # in a unique root-owned tmpfs directory. A lane command can modify /work, so
    # no liveness decision may trust a marker stored there.
    shell = (
        "set -eu; c=$1; w=$2; shift 2; ulimit -f 131072; umask 077; "
        "[ ! -e \"$c\" ] && [ ! -L \"$c\" ]; mkdir -- \"$c\"; chmod 0700 \"$c\"; "
        "r=/work/.ctf-sessions; [ ! -L \"$r\" ]; "
        "install -d -m 0700 -o 1001 -g 1001 \"$r\"; "
        "setpriv --reuid=1001 --regid=1001 --clear-groups "
        "sh -c 'umask 077; [ ! -e \"$1\" ] && [ ! -L \"$1\" ]; "
        "mkdir -- \"$1\"; mkfifo -m 0600 \"$1/in\"; : >\"$1/out\"' "
        "ctf-os-session-work \"$w\"; "
        "setpriv --reuid=1001 --regid=1001 --clear-groups "
        "sh -c 'exec tail -f /dev/null >\"$1\"' ctf-os-session-keeper \"$w/in\" & k=$!; "
        "kst=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
        "print(s[s.rfind(\") \")+2:].split()[19])' \"$k\"); "
        "printf '%s %s\\n' \"$k\" \"$kst\" >\"$c/keeper\"; "
        "python3 -I -c 'import os,sys; os.setgroups([]); os.setgid(1001); os.setuid(1001); "
        "os.setsid(); w=sys.argv[1]; i=os.open(w+\"/in\",os.O_RDONLY); "
        "o=os.open(w+\"/out\",os.O_WRONLY|os.O_APPEND); os.dup2(i,0); "
        "os.dup2(o,1); os.dup2(o,2); os.execvp(sys.argv[2], sys.argv[2:])' "
        "\"$w\" \"$@\" & p=$!; "
        "pinfo=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
        "v=s[s.rfind(\") \")+2:].split(); print(v[0],v[19])' \"$p\"); "
        "pst=${pinfo%% *}; st=${pinfo#* }; [ \"$pst\" != Z ]; "
        "printf '%s %s\\n' \"$p\" \"$st\" >\"$c/identity\"; "
        "printf '%s %s %s\\n' \"$(date +%s)\" \"$p\" \"$st\" >\"$c/heartbeat\"; "
        "( while :; do "
        "info=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
        "v=s[s.rfind(\") \")+2:].split(); print(v[0],v[19])' \"$p\" 2>/dev/null || true); "
        "state=${info%% *}; cur=${info#* }; "
        "[ -n \"$info\" ] && [ \"$state\" != Z ] && [ \"$cur\" = \"$st\" ] || break; "
        "printf '%s %s %s\\n' \"$(date +%s)\" \"$p\" \"$st\" >\"$c/heartbeat.next\"; "
        "mv -f \"$c/heartbeat.next\" \"$c/heartbeat\"; sleep 2; done; "
        "printf 'dead\\n' >\"$c/exit\" ) & m=$!; "
        "mst=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
        "print(s[s.rfind(\") \")+2:].split()[19])' \"$m\"); "
        "printf '%s %s\\n' \"$m\" \"$mst\" >\"$c/monitor\""
    )
    result = _run(
        runner,
        [
            *controller_exec_prefix(
                metadata, docker=docker, detach=True, workdir="/work",
            ),
            "sh", "-c", shell, "ctf-os-session", controller_dir, container_dir, *argv,
        ],
        timeout=30,
    )
    if result.returncode:
        raise SessionError(f"persistent session start failed: {result.stderr.strip()}")
    identity_result = _run(
        runner,
        [
            *controller_exec_prefix(metadata, docker=docker),
            "sh", "-c",
            (
                "i=0; while [ \"$i\" -lt 50 ]; do "
                "[ -f \"$1/identity\" ] && { cat \"$1/identity\"; exit 0; }; "
                "i=$((i+1)); sleep 0.1; done; exit 1"
            ),
            "ctf-os-session-identity", controller_dir,
        ],
        timeout=10,
    )
    try:
        pid_text, start_time = identity_result.stdout.strip().split()
        pid = int(pid_text)
        if (
            identity_result.returncode
            or pid <= 0
            or not start_time.isdigit()
            or int(start_time) <= 0
        ):
            raise ValueError
    except ValueError:
        diagnostic = _session_start_diagnostic(
            metadata,
            controller_dir=controller_dir,
            container_dir=container_dir,
            docker=docker,
            runner=runner,
        )
        _discard_started_session(
            metadata,
            controller_dir=controller_dir,
            container_dir=container_dir,
            docker=docker,
            runner=runner,
        )
        detail = (identity_result.stderr + diagnostic).strip()
        raise SessionError(
            "persistent session did not publish a valid process identity"
            + (f": {detail[-2048:]}" if detail else "")
        )
    state = {
        "schema_version": 1,
        "session_id": session_id,
        "run_id": metadata["run_id"],
        "lane_id": metadata["lane_id"],
        "kind": kind,
        "argv": argv,
        "target_identity": observed_identity,
        "target_packets_before": packets_before,
        "container_dir": container_dir,
        "controller_dir": controller_dir,
        "container_name": metadata["name"],
        "pid": pid,
        "pid_start_time": start_time,
        "cursor": 0,
        "status": "RUNNING",
        "opened_at": _now(),
    }
    state_path.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        atomic_json(state_path, state)
    except Exception:
        _discard_started_session(
            metadata,
            controller_dir=controller_dir,
            container_dir=container_dir,
            docker=docker,
            runner=runner,
        )
        raise
    return state


def send(
    metadata: Mapping[str, Any],
    *,
    session_id: str,
    data: str,
    timeout: int = 10,
    docker: str = "docker",
) -> dict[str, Any]:
    if not data or len(data.encode()) > MAX_READ:
        raise SessionError("session send must contain 1..65536 bytes")
    state = _load_state(metadata, session_id)
    argv = [
        *user_exec_prefix(metadata, docker=docker, interactive=True),
        "sh", "-c", "cat >\"$1/in\"", "ctf-os-send", state["container_dir"],
    ]
    try:
        result = subprocess.run(
            argv, input=data, capture_output=True, text=True, timeout=_timeout(timeout), check=False
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise SessionError(f"session send failed: {exc}") from exc
    if result.returncode:
        raise SessionError(f"session send failed: {result.stderr.strip()}")
    return {"session_id": session_id, "bytes_sent": len(data.encode()), "sent_at": _now()}


def read(
    metadata: Mapping[str, Any],
    *,
    session_id: str,
    limit: int = MAX_READ,
    timeout: int = 10,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if limit < 1 or limit > MAX_READ:
        raise SessionError("session read limit must be between 1 and 65536 bytes")
    state = _load_state(metadata, session_id)
    # The bounded tail of the previous durable read lets the caller detect a flag
    # that straddles this read's boundary, provably backed by that prior receipt.
    prior_tail = str(state.get("detector_tail", "") or "")
    prior_tail_receipt_id = state.get("detector_tail_receipt_id")
    started_at = _now()
    script = (
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); o=int(sys.argv[2]); n=int(sys.argv[3]); "
        "b=p.read_bytes(); c=b[o:o+n]; sys.stdout.buffer.write(c); print(len(c),len(b),file=sys.stderr)"
    )
    argv = [
        *user_exec_prefix(metadata, docker=docker),
        "python3", "-c", script, f"{state['container_dir']}/out", str(state["cursor"]), str(limit),
    ]
    result = _run(runner, argv, timeout=_timeout(timeout))
    if result.returncode:
        raise SessionError(f"session read failed: {result.stderr.strip()}")
    output = result.stdout
    cursor_before = int(state["cursor"])
    try:
        counts = [int(value) for value in result.stderr.strip().split()[-2:]]
    except ValueError:
        counts = []
    if len(counts) == 2:
        chunk_bytes, total_bytes = counts
    else:
        chunk_bytes = len(output.encode())
        total_bytes = cursor_before + chunk_bytes
    if chunk_bytes < 0 or chunk_bytes > limit or total_bytes < cursor_before + chunk_bytes:
        raise SessionError("session read returned invalid bounded byte counts")
    packets_after = firewall_packets(metadata, str(state["target_identity"]), docker=docker)
    target_observed, observation_source = target_observation(
        metadata,
        str(state["target_identity"]),
        before_packets=(
            int(state["target_packets_before"])
            if state.get("target_packets_before") is not None
            else None
        ),
        after_packets=packets_after,
    )
    liveness = session_liveness(
        Path(str(metadata["lane_root"])),
        state,
        now_epoch=datetime.now(UTC).timestamp(),
        docker=docker,
        runner=runner,
    )
    receipt_id = uuid.uuid4().hex
    state["cursor"] = cursor_before + chunk_bytes
    state["last_read_at"] = _now()
    # Carry this read's trailing bytes forward so the next read can detect a flag
    # that begins here and completes there; the receipt id ties the tail to this
    # durable output for tamper-evident boundary verification.
    state["detector_tail"] = output[-MAX_FLAG_TAIL:]
    state["detector_tail_receipt_id"] = receipt_id
    # Draining a dead session's buffered output stays valid, but once the process
    # has exited we reflect STOPPED so it never reads as infinitely RUNNING.
    if liveness.get("reason") == "exited":
        state["status"] = "STOPPED"
        state["stopped_at"] = _now()
        state["stopped_reason"] = "process-exited"
    atomic_json(_state_path(Path(str(metadata["lane_root"])), session_id), state)
    logs = Path(str(metadata["lane_root"])) / "logs"
    output_path = logs / f"{receipt_id}.session.txt"
    atomic_text(output_path, output)
    receipt = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "run_id": metadata["run_id"],
        "lane_id": metadata["lane_id"],
        "argv": [f"session:{session_id}", "read"],
        "argv_family": f"session:{state['kind']}:read",
        "exit_code": result.returncode,
        "observed_output": output,
        "output_hash": output_hash(output),
        "target_identity": state["target_identity"],
        "target_observed": target_observed,
        "observation_source": observation_source,
        "target_packets_before": state.get("target_packets_before"),
        "target_packets_after": packets_after,
        "started_at": started_at,
        "finished_at": _now(),
        "session_id": session_id,
        "session_live": bool(liveness["live"]),
        "session_prior_tail": prior_tail,
        "session_prior_receipt_id": prior_tail_receipt_id,
        "output_truncated": total_bytes > int(state["cursor"]),
        "output_artifact": str(output_path.relative_to(Path(str(metadata["lane_root"])))),
    }
    atomic_json(logs / f"{receipt_id}.json", receipt)
    return receipt


def close_session(
    metadata: Mapping[str, Any],
    *,
    session_id: str,
    timeout: int = 10,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    # Idempotent: a session that already reached STOPPED can be closed again to
    # retry resource cleanup without erroring.
    state = _load_state(metadata, session_id, require_running=False)
    controller_dir = str(state.get("controller_dir", ""))
    if _CONTROLLER_DIR.fullmatch(controller_dir):
        script = _CONTROLLER_CLEANUP_SCRIPT
        prefix = controller_exec_prefix(metadata, docker=docker)
        arguments = [controller_dir, str(state["container_dir"])]
    else:
        # Backward-compatible cleanup for session records created by an older
        # controller. Legacy records are never considered live because they have
        # no root-owned identity, but their work files remain safely removable.
        script = (
            "d=$1; for f in pid keeper; do p=$(cat \"$d/$f\" 2>/dev/null || true); "
            "[ -n \"$p\" ] && kill -TERM -\"$p\" 2>/dev/null || "
            "kill -TERM \"$p\" 2>/dev/null || true; done; rm -rf -- \"$d\""
        )
        prefix = user_exec_prefix(metadata, docker=docker)
        arguments = [str(state["container_dir"])]
    result = _run(
        runner,
        [
            *prefix,
            "sh", "-c", script, "ctf-os-close", *arguments,
        ],
        timeout=_timeout(timeout),
    )
    if result.returncode == 0:
        state["status"] = "STOPPED"
        state["closed_at"] = _now()
        atomic_json(_state_path(Path(str(metadata["lane_root"])), session_id), state)
    return {"session_id": session_id, "stopped": result.returncode == 0, "stderr": result.stderr[-4096:]}


def list_sessions(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    lane_root = Path(str(metadata["lane_root"]))
    root = lane_root / "sessions"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise SessionError("session state directory is unsafe")
    now_epoch = datetime.now(UTC).timestamp()
    rows = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink():
            raise SessionError("session state contains a symlink")
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            liveness = session_liveness(lane_root, value, now_epoch=now_epoch)
            value["live"] = bool(liveness["live"])
            # A RUNNING record whose process has exited is reflected as STOPPED so
            # it never reads as an infinitely live session.
            if value.get("status") == "RUNNING" and liveness.get("reason") == "exited":
                _mark_session_stopped(metadata, value)
        rows.append(value)
    return rows


def list_tools(category: str) -> dict[str, Any]:
    tools = tuple(dict.fromkeys(_TOOLS["base"] + _TOOLS.get(category, ())))
    return {"category": category, "tools": list(tools), "discovery": ["tool-help <name>", "tool-version <name>"]}


def tool_help(category: str, name: str) -> dict[str, str]:
    if name not in list_tools(category)["tools"]:
        raise SessionError("tool is not exposed for this category")
    return {"tool": name, "hint": _HELP.get(name, f"Run {name} --help inside the assigned sandbox for bounded usage details.")}


def tool_version(
    metadata: Mapping[str, Any],
    name: str,
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    if name not in list_tools(str(metadata["category"]))["tools"]:
        raise SessionError("tool is not exposed for this category")
    command = _VERSION_COMMANDS.get(name, (name, "--version"))
    result = _run(
        runner,
        [*user_exec_prefix(metadata, docker=docker), *command],
        timeout=20,
    )
    return {"tool": name, "available": result.returncode == 0, "output": (result.stdout + result.stderr)[-4096:]}


def session_liveness(
    lane_root: Path,
    state: Mapping[str, Any],
    *,
    now_epoch: float,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Return liveness from a controller-owned identity and process probe.

    The probe runs as the container controller and reads only a root-owned tmpfs
    directory. It also rereads /proc/<pid>/stat on every call, so a writable
    /work marker or a reused PID can never keep a dead session in flight.
    """

    Path(lane_root).resolve()
    session_id = str(state.get("session_id", ""))
    if not _SESSION_ID.fullmatch(session_id):
        return {"live": False, "reason": "invalid-session-id"}
    if str(state.get("status")) != "RUNNING":
        return {"live": False, "reason": "not-running"}
    controller_dir = str(state.get("controller_dir", ""))
    if not _CONTROLLER_DIR.fullmatch(controller_dir):
        return {"live": False, "reason": "unowned-heartbeat"}
    try:
        expected_pid = int(state["pid"])
        expected_start = str(state["pid_start_time"])
    except (KeyError, TypeError, ValueError):
        return {"live": False, "reason": "unpinned-identity"}
    if expected_pid <= 0 or not expected_start.isdigit() or int(expected_start) <= 0:
        return {"live": False, "reason": "unpinned-identity"}
    container_name = str(state.get("container_name", ""))
    probe_metadata = {"name": container_name}
    probe_script = (
        "d=$1; ep=$2; es=$3; "
        "[ -d \"$d\" ] && [ ! -L \"$d\" ] || { echo missing-controller-state; exit 0; }; "
        "[ ! -e \"$d/exit\" ] || { echo exited; exit 0; }; "
        "read epoch pid start <\"$d/heartbeat\" 2>/dev/null || { echo no-heartbeat; exit 0; }; "
        "[ \"$pid\" = \"$ep\" ] || { echo pid-mismatch; exit 0; }; "
        "[ \"$start\" = \"$es\" ] || { echo pid-reused; exit 0; }; "
        "info=$(python3 -I -c 'import pathlib,sys; s=pathlib.Path(\"/proc/\"+sys.argv[1]+\"/stat\").read_text(); "
        "v=s[s.rfind(\") \")+2:].split(); print(v[0],v[19])' \"$pid\" 2>/dev/null || true); "
        "state=${info%% *}; cur=${info#* }; "
        "[ -n \"$info\" ] && [ \"$state\" != Z ] || { echo exited; exit 0; }; "
        "[ \"$cur\" = \"$start\" ] || { echo pid-reused; exit 0; }; "
        "printf 'live %s %s %s\\n' \"$epoch\" \"$pid\" \"$start\""
    )
    try:
        result = _run(
            runner,
            [
                *controller_exec_prefix(probe_metadata, docker=docker),
                "sh", "-c", probe_script, "ctf-os-session-live",
                controller_dir, str(expected_pid), expected_start,
            ],
            timeout=10,
        )
    except (SandboxError, SessionError, ValueError):
        return {"live": False, "reason": "probe-failed"}
    if result.returncode:
        return {"live": False, "reason": "probe-failed"}
    parts = result.stdout.strip().split()
    if not parts:
        return {"live": False, "reason": "malformed-heartbeat"}
    if parts[0] != "live":
        reason = parts[0]
        if reason in {
            "exited", "missing-controller-state", "no-heartbeat",
            "pid-mismatch", "pid-reused",
        }:
            return {"live": False, "reason": reason}
        return {"live": False, "reason": "malformed-heartbeat"}
    if len(parts) != 4:
        return {"live": False, "reason": "malformed-heartbeat"}
    try:
        epoch = float(parts[1])
        pid = int(parts[2])
    except ValueError:
        return {"live": False, "reason": "malformed-heartbeat"}
    start_time = parts[3]
    if pid != expected_pid:
        return {"live": False, "reason": "pid-mismatch"}
    if start_time != expected_start:
        return {"live": False, "reason": "pid-reused"}
    if epoch > now_epoch + 5 or now_epoch - epoch > SESSION_HEARTBEAT_STALE_SECONDS:
        return {"live": False, "reason": "stale-heartbeat", "heartbeat_at": epoch}
    return {
        "live": True, "pid": pid, "pid_start_time": start_time, "heartbeat_at": epoch,
    }


def _load_state(
    metadata: Mapping[str, Any], session_id: str, *, require_running: bool = True
) -> dict[str, Any]:
    _validate_session_id(session_id)
    path = _state_path(Path(str(metadata["lane_root"])), session_id)
    if path.is_symlink() or not path.is_file():
        raise SessionError("persistent session is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SessionError("persistent session schema is unsupported")
    if value.get("run_id") != metadata.get("run_id") or value.get("lane_id") != metadata.get("lane_id"):
        raise SessionError("persistent session identity mismatch")
    if require_running and value.get("status") != "RUNNING":
        raise SessionError("persistent session is not running")
    return value


def _discard_started_session(
    metadata: Mapping[str, Any],
    *,
    controller_dir: str,
    container_dir: str,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Best-effort cleanup when session startup cannot become durable."""

    try:
        _run(
            runner,
            [
                *controller_exec_prefix(metadata, docker=docker),
                "sh", "-c", _CONTROLLER_CLEANUP_SCRIPT,
                "ctf-os-session-discard", controller_dir, container_dir,
            ],
            timeout=10,
        )
    except SessionError:
        pass


def _session_start_diagnostic(
    metadata: Mapping[str, Any],
    *,
    controller_dir: str,
    container_dir: str,
    docker: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    """Return bounded startup evidence before a failed detached exec is removed."""

    try:
        result = _run(
            runner,
            [
                *controller_exec_prefix(metadata, docker=docker),
                "sh", "-c",
                (
                    "printf 'controller: '; ls -la \"$1\" 2>&1 || true; "
                    "printf 'session output: '; tail -c 1024 \"$2/out\" 2>&1 || true"
                ),
                "ctf-os-session-diagnostic", controller_dir, container_dir,
            ],
            timeout=10,
        )
    except SessionError as exc:
        return str(exc)
    return (result.stdout + result.stderr)[-2048:]


def _mark_session_stopped(metadata: Mapping[str, Any], state: dict[str, Any]) -> None:
    """Atomically reflect that a session process has exited."""

    if state.get("status") != "RUNNING":
        return
    state["status"] = "STOPPED"
    state["stopped_at"] = _now()
    state["stopped_reason"] = "process-exited"
    atomic_json(
        _state_path(Path(str(metadata["lane_root"])), str(state["session_id"])), state
    )


def _state_path(lane_root: Path, session_id: str) -> Path:
    return lane_root.resolve() / "sessions" / f"{session_id}.json"


def _validate_session_id(value: str) -> None:
    if not _SESSION_ID.fullmatch(value):
        raise SessionError("session id must be a bounded lowercase identifier")


def _timeout(value: int) -> int:
    if value < 1 or value > 60:
        raise SessionError("interactive timeout must be between 1 and 60 seconds")
    return value


def _run(
    runner: Callable[..., subprocess.CompletedProcess[str]], argv: Sequence[str], *, timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(argv), capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise SessionError(f"required executable not found: {argv[0]}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SessionError(f"interactive controller command failed: {exc}") from exc


def _now() -> str:
    return datetime.now(UTC).isoformat()
