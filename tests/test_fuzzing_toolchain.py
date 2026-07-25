from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from ctf_os.sandbox import session
from ctf_os.sandbox.session import list_tools, tool_help, tool_version

P0_TOOLS = {
    "pwn": {
        "afl-fuzz", "afl-showmap", "afl-cmin", "afl-tmin",
        "afl-qemu-trace", "ROPgadget", "ropper", "one_gadget", "patchelf",
        "ltrace", "qemu-aarch64", "qemu-system-x86_64",
    },
    "web": {
        "dalfox", "chromium", "chromedriver", "node", "npm", "php",
        "sqlite3", "redis-cli", "psql", "mysql",
    },
    "rev": {
        "jadx", "apktool", "frida", "upx", "wasm-objdump", "wasm2wat",
        "wasmtime", "qemu-aarch64", "qemu-system-aarch64", "capa",
    },
    "cloud": {
        "aws", "az", "gcloud", "kubectl", "helm", "terraform", "tofu",
        "podman", "skopeo", "oras", "cosign", "trivy", "syft", "grype",
        "kustomize", "opa", "conftest", "checkov", "semgrep",
    },
}

INSTALL_REQUIRED_COMMANDS = {
    "base": {
        "python3", "curl", "wget", "git", "jq", "rg", "file", "objdump",
        "strings", "readelf", "nm", "xxd", "nmap", "gcc", "g++", "cmake",
        "clang", "ruby", "java",
    },
    "pwn": {
        "ctf-ghidra-headless", "capa", "frida", "frida-ps", "gdb",
        "gdb-multiarch", "pwndbg", "patchelf", "checksec", "ROPgadget",
        "ropper", "one_gadget", "pwninit", "seccomp-tools", "musl-gcc",
        "qemu-aarch64", "qemu-arm", "qemu-mips", "qemu-mipsel",
        "qemu-riscv64", "qemu-system-x86_64", "qemu-system-aarch64",
        "cpio", "afl-fuzz", "afl-showmap", "afl-clang-fast",
        "afl-clang-fast++", "afl-qemu-trace", "valgrind", "boo", "cargo",
        "cargo-fuzz", "rustc",
    },
    "web": {
        "node", "npm", "php", "sqlite3", "redis-cli", "psql", "mysql",
        "chromium", "chromedriver", "ffuf", "nuclei", "ctf-nuclei-scan",
        "dalfox", "semgrep", "sqlmap", "sstimap", "schemathesis",
    },
    "rev": {
        "java", "javac", "analyzeHeadless", "ctf-ghidra-headless", "frida",
        "frida-ps", "capa", "r2", "gdb", "gdb-multiarch", "jadx",
        "jadx-gui", "apktool", "wasm-objdump", "upx", "wasmtime", "mono",
        "qemu-aarch64", "qemu-arm", "qemu-mips", "qemu-mipsel",
        "qemu-riscv64", "qemu-system-x86_64", "qemu-system-aarch64",
        "qemu-system-riscv64", "qemu-img", "jazzer",
    },
    "crypto": {
        "sage", "RsaCtfTool", "cado-nfs", "gp", "gap", "maxima", "hashcat",
        "ares",
    },
    "forensic": {
        "vol", "mmls", "fls", "icat", "foremost", "exiftool", "binwalk",
        "tshark", "tcpdump", "testdisk", "photorec", "dcfldd", "steghide",
        "stegseek", "zsteg", "convert", "tesseract", "pngcheck", "ffmpeg",
        "sox",
    },
    "misc": {
        "ffmpeg", "sox", "convert", "tesseract", "tshark", "binwalk",
        "exiftool", "dot", "parallel", "podman", "zbarimg", "barcode", "php",
        "lua", "perl", "node", "npm", "ares",
    },
    "osint": {
        "whois", "dig", "nslookup", "host", "traceroute", "chromium",
        "exiftool", "convert", "tesseract", "ffmpeg", "yt-dlp", "git-lfs",
        "pdftotext", "waybackurls", "sherlock", "maigret", "holehe",
        "theHarvester",
    },
    "ai": {
        "protoc", "h5dump", "ncdump", "dot", "jupyter", "modelscan",
        "fickling",
    },
    "cloud": {
        "aws", "az", "gcloud", "kubectl", "helm", "terraform", "tofu",
        "podman", "skopeo", "oras", "cosign", "trivy", "syft", "grype",
        "kustomize", "opa", "conftest", "checkov", "semgrep", "yq",
    },
}


def test_p0_installed_commands_are_exposed_with_help() -> None:
    for category, expected in P0_TOOLS.items():
        exposed = set(list_tools(category)["tools"])
        assert expected <= exposed
        for name in expected:
            assert tool_help(category, name)["hint"]


def test_every_installer_required_solver_command_is_exposed_with_help() -> None:
    for category, required in INSTALL_REQUIRED_COMMANDS.items():
        exposed = set(list_tools(category)["tools"])
        assert required <= exposed, (
            category,
            sorted(required - exposed),
        )
        for name in required:
            assert tool_help(category, name)["hint"].strip()


def test_every_catalog_entry_has_help_and_a_probe_command() -> None:
    for category in session._TOOLS:
        for name in list_tools(category)["tools"]:
            assert tool_help(category, name)["hint"].strip()
            command = session._VERSION_COMMANDS.get(name, (name, "--version"))
            assert command and all(command)


def test_p1_and_p2_tools_are_exposed_only_in_their_selected_images() -> None:
    placements = {
        "pwn": {"valgrind", "boo", "atheris", "cargo-fuzz"},
        "web": {"schemathesis"},
        "rev": {"jazzer"},
    }
    for category, expected in placements.items():
        assert expected <= set(list_tools(category)["tools"])
    assert "valgrind" not in list_tools("rev")["tools"]
    assert "schemathesis" not in list_tools("base")["tools"]
    assert "jazzer" not in list_tools("pwn")["tools"]


def test_catalog_has_no_duplicates_or_base_redeclarations() -> None:
    base = set(session._TOOLS["base"])
    for category, declared in session._TOOLS.items():
        assert len(declared) == len(set(declared)), category
        if category != "base":
            assert not base.intersection(declared), category
        exposed = list_tools(category)["tools"]
        assert len(exposed) == len(set(exposed)), category


def test_explicitly_excluded_fuzzers_are_not_advertised() -> None:
    excluded = {"syzkaller", "Fuzzilli", "RESTler", "honggfuzz", "LibAFL"}
    exposed = {
        tool
        for category in session._TOOLS
        for tool in list_tools(category)["tools"]
    }
    assert not excluded.intersection(exposed)


@pytest.mark.parametrize(
    ("category", "name", "expected_tail"),
    (
        (
            "pwn",
            "afl-fuzz",
            (
                "sh", "-ec",
                "command -v afl-fuzz >/dev/null; grep '^aflplusplus=' /opt/ctf-os/tool-versions.lock",
            ),
        ),
        (
            "pwn",
            "atheris",
            (
                "python3", "-c",
                "from importlib.metadata import version; print(version('atheris'))",
            ),
        ),
        (
            "pwn",
            "ropper",
            (
                "sh", "-ec",
                "command -v ropper >/dev/null; python3 -c \"from importlib.metadata import version; print(version('ropper'))\"",
            ),
        ),
        ("pwn", "cargo-fuzz", ("cargo-fuzz", "--version")),
        ("web", "schemathesis", ("schemathesis", "--version")),
        ("rev", "jazzer", ("jazzer", "--version")),
        ("cloud", "aws", ("aws", "--version")),
        ("cloud", "az", ("az", "version")),
        ("cloud", "kubectl", ("kubectl", "version", "--client=true")),
        ("cloud", "helm", ("helm", "version", "--short")),
        ("cloud", "oras", ("oras", "version")),
    ),
)
def test_catalog_uses_offline_exact_version_probes(
    category: str, name: str, expected_tail: tuple[str, ...]
) -> None:
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "version\n", "")

    metadata = {"category": category, "name": f"ctf-os-{category}"}
    assert tool_version(metadata, name, runner=runner)["available"] is True
    assert tuple(calls[0][-len(expected_tail):]) == expected_tail


def test_new_tool_versions_and_artifacts_are_pinned() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    lock = (repo_root / "sandbox" / "tool-versions.lock").read_text(encoding="utf-8")
    required = {
        "valgrind_debian_version=1:3.19.0-1",
        "boofuzz=0.4.2",
        "atheris=3.0.0",
        "schemathesis=4.24.2",
        "jazzer=0.30.0",
        "rust_nightly=2026-06-10",
        "cargo-fuzz=0.13.2",
        "libfuzzer-sys=0.4.13",
    }
    assert required <= set(lock.splitlines())
    for line in lock.splitlines():
        if "_sha256=" in line:
            assert len(line.rsplit("=", 1)[1]) == 64


def test_cargo_wrapper_separates_build_root_state_from_runtime_home() -> None:
    wrapper = Path("sandbox/bin/ctf-cargo").read_text(encoding="utf-8")

    assert 'elif [ "$(id -u)" -eq 0 ]; then' in wrapper
    assert 'runtime_cargo_home="/tmp/ctf-os-build-cargo"' in wrapper
    assert 'runtime_cargo_home="/work/home/.cargo"' in wrapper
    assert 'runtime_cargo_home="${CARGO_HOME:-/work/.cargo}"' not in wrapper


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
@pytest.mark.parametrize(
    ("profile", "command"),
    (
        ("pwn", "/usr/local/bin/ctf-os-pwn-fuzzing-smoke"),
        ("web", "schemathesis"),
        ("rev", "/usr/local/bin/ctf-os-rev-fuzzing-smoke"),
    ),
)
def test_new_fuzzers_run_in_hardened_category_containers(
    profile: str, command: str
) -> None:
    argv = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--memory", "4g", "--pids-limit", "512", "--user", "1001:1001",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=2g,mode=0700,uid=1001,gid=1001",
        "--tmpfs", "/artifacts:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001",
    ]
    if profile in {"pwn", "rev"}:
        argv.extend(["--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined"])
    argv.extend(["--entrypoint", command, f"ctf-os-sandbox:{profile}"])
    if profile == "web":
        argv.append("--version")
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
