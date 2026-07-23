"""Bounded persistent shell, remote, and debugger sessions inside one lane."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping, Sequence
import uuid

from ..blackboard import output_hash
from ..workspace import atomic_json, atomic_text
from .runtime import firewall_packets


SESSION_KINDS = frozenset({"shell", "remote", "debugger"})
MAX_READ = 64 * 1024
_SESSION_ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,47}\Z")

_TOOLS: dict[str, tuple[str, ...]] = {
    "base": ("bash", "python3", "rg", "file", "strings", "xxd", "curl", "nc", "socat"),
    "pwn": ("python3", "gdb", "pwndbg", "checksec", "pwninit", "angrop", "seccomp-tools", "objdump", "readelf", "strace"),
    "web": ("curl", "httpx", "nuclei", "semgrep", "sqlmap", "ffuf", "sstimap", "python3"),
    "rev": ("gdb", "ctf-ghidra-headless", "capa", "r2", "objdump", "qemu-x86_64", "python3"),
    "crypto": ("python3", "sage", "openssl", "z3", "ares"),
    "forensic": ("file", "binwalk", "exiftool", "tshark", "vol", "foremost", "stegseek", "python3"),
    "misc": ("python3", "ffmpeg", "sox", "zbarimg", "tesseract", "file", "ares"),
    "osint": (
        "whois", "dig", "curl", "tesseract", "exiftool", "sherlock", "maigret",
        "holehe", "theHarvester", "python3",
    ),
    "ai": ("python3", "onnxruntime", "safetensors", "pickletools"),
    "cloud": ("terraform", "kubectl", "helm", "opa", "conftest", "checkov", "podman"),
}
_HELP = {
    "ctf-ghidra-headless": "ctf-ghidra-headless INPUT [TIMEOUT_SECONDS] exports bounded decompilation.",
    "nuclei": "Use ctf-nuclei-scan with the bundled offline challenge templates.",
    "gdb": "Use gdb in a persistent debugger session for interactive breakpoints and memory inspection.",
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
}
_VERSION_COMMANDS: dict[str, tuple[str, ...]] = {
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
    "httpx": (
        "python3", "-c",
        "from importlib.metadata import version; print(version('httpx'))",
    ),
    "semgrep": (
        "sh", "-ec",
        "grep '^semgrep=' /opt/ctf-os/tool-versions.lock",
    ),
    "ffuf": ("ffuf", "-V"),
    "ctf-ghidra-headless": (
        "sh", "-ec",
        "grep '^ghidra=' /opt/ctf-os/tool-versions.lock",
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
    observed_identity = target_identity or f"challenge:{metadata['challenge_id']}"
    packets_before = firewall_packets(metadata, observed_identity, docker=docker)
    shell = (
        "set -eu; d=$1; shift; ulimit -f 131072; "
        "mkdir -p \"$d\"; mkfifo \"$d/in\"; : >\"$d/out\"; "
        "(tail -f /dev/null >\"$d/in\") & echo $! >\"$d/keeper\"; "
        "setsid \"$@\" <\"$d/in\" >>\"$d/out\" 2>&1 & echo $! >\"$d/pid\""
    )
    result = _run(
        runner,
        [
            docker, "exec", "--detach", "--user", "1001:1001", "--workdir", "/work",
            str(metadata["name"]), "sh", "-c", shell, "ctf-os-session", container_dir, *argv,
        ],
        timeout=30,
    )
    if result.returncode:
        raise SessionError(f"persistent session start failed: {result.stderr.strip()}")
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
        "cursor": 0,
        "status": "RUNNING",
        "opened_at": _now(),
    }
    state_path.parent.mkdir(mode=0o700, exist_ok=True)
    atomic_json(state_path, state)
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
        docker, "exec", "--interactive", "--user", "1001:1001", str(metadata["name"]),
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
    started_at = _now()
    script = (
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); o=int(sys.argv[2]); n=int(sys.argv[3]); "
        "b=p.read_bytes(); c=b[o:o+n]; sys.stdout.buffer.write(c); print(len(c),len(b),file=sys.stderr)"
    )
    argv = [
        docker, "exec", "--user", "1001:1001", str(metadata["name"]),
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
    target_observed = (
        state["target_identity"] == f"challenge:{metadata['challenge_id']}"
        or (
            state.get("target_packets_before") is not None and packets_after is not None
            and int(packets_after) > int(state["target_packets_before"])
        )
    )
    state["cursor"] = cursor_before + chunk_bytes
    state["last_read_at"] = _now()
    atomic_json(_state_path(Path(str(metadata["lane_root"])), session_id), state)
    receipt_id = uuid.uuid4().hex
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
        "target_packets_before": state.get("target_packets_before"),
        "target_packets_after": packets_after,
        "started_at": started_at,
        "finished_at": _now(),
        "session_id": session_id,
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
    state = _load_state(metadata, session_id)
    script = (
        "d=$1; for f in pid keeper; do p=$(cat \"$d/$f\" 2>/dev/null || true); "
        "[ -n \"$p\" ] && kill -TERM -\"$p\" 2>/dev/null || kill -TERM \"$p\" 2>/dev/null || true; done; "
        "rm -rf -- \"$d\""
    )
    result = _run(
        runner,
        [docker, "exec", "--user", "1001:1001", str(metadata["name"]), "sh", "-c", script, "ctf-os-close", state["container_dir"]],
        timeout=_timeout(timeout),
    )
    if result.returncode == 0:
        state["status"] = "STOPPED"
        state["closed_at"] = _now()
        atomic_json(_state_path(Path(str(metadata["lane_root"])), session_id), state)
    return {"session_id": session_id, "stopped": result.returncode == 0, "stderr": result.stderr[-4096:]}


def list_sessions(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = Path(str(metadata["lane_root"])) / "sessions"
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise SessionError("session state directory is unsafe")
    rows = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink():
            raise SessionError("session state contains a symlink")
        rows.append(json.loads(path.read_text(encoding="utf-8")))
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
        [docker, "exec", "--user", "1001:1001", str(metadata["name"]), *command],
        timeout=20,
    )
    return {"tool": name, "available": result.returncode == 0, "output": (result.stdout + result.stderr)[-4096:]}


def _load_state(metadata: Mapping[str, Any], session_id: str) -> dict[str, Any]:
    _validate_session_id(session_id)
    path = _state_path(Path(str(metadata["lane_root"])), session_id)
    if path.is_symlink() or not path.is_file():
        raise SessionError("persistent session is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SessionError("persistent session schema is unsupported")
    if value.get("run_id") != metadata.get("run_id") or value.get("lane_id") != metadata.get("lane_id"):
        raise SessionError("persistent session identity mismatch")
    if value.get("status") != "RUNNING":
        raise SessionError("persistent session is not running")
    return value


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
    return datetime.now(timezone.utc).isoformat()
