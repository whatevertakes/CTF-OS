"""Pre-contest, read-mostly infrastructure checks with actionable fixes."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

from .sandbox.runtime import SandboxSpec, cleanup, create, execute


IMAGES = tuple(f"ctf-os-sandbox:{name}" for name in ("base", "pwn", "web", "rev", "crypto", "forensic"))


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def run_doctor(repo: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []

    def add(name: str, ok: bool, detail: str, fix: str | None = None) -> None:
        item: dict[str, object] = {"name": name, "ok": ok, "detail": detail}
        if not ok and fix:
            item["fix"] = fix
        checks.append(item)

    for executable in ("python3", "uv", "docker"):
        path = shutil.which(executable)
        add(executable, bool(path), path or "not found", f"install {executable} and place it on PATH")
    docker = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    add("docker-daemon", docker.returncode == 0, docker.stdout.strip() or docker.stderr.strip(), "start the Docker daemon")
    compose = _run(["docker", "compose", "version", "--short"])
    add("docker-compose", compose.returncode == 0, compose.stdout.strip() or compose.stderr.strip(), "install Docker Compose v2")

    images = _run(["docker", "image", "inspect", *IMAGES]) if docker.returncode == 0 else subprocess.CompletedProcess([], 1, "", "daemon unavailable")
    add("category-images", images.returncode == 0, "all six tags present" if images.returncode == 0 else images.stderr.strip(), "run sandbox/build-images.sh")
    if images.returncode == 0:
        probes = {
            "base": "command -v python3 && command -v jq && command -v rg",
            "pwn": "command -v gdb && command -v patchelf && python3 -c 'import pwn'",
            "web": "command -v node && command -v php && command -v sqlite3 && python3 -c 'import flask,fastapi,jwt'",
            "rev": "command -v r2 && python3 -c 'import angr'",
            "crypto": "command -v gp && python3 -c 'import gmpy2,fpylll,z3,Crypto'",
            "forensic": "binwalk --help >/dev/null && command -v tshark && python3 -c 'import volatility3'",
        }
        for profile, command in probes.items():
            smoke = _run(["docker", "run", "--rm", "--network", "none", f"ctf-os-sandbox:{profile}", "sh", "-c", command], timeout=60)
            add(f"image-{profile}-tools", smoke.returncode == 0, smoke.stdout.strip() or smoke.stderr.strip() or "probe passed", f"rebuild ctf-os-sandbox:{profile}")
        lifecycle_ok, lifecycle_detail = _sandbox_lifecycle_probe()
        add("sandbox-lifecycle", lifecycle_ok, lifecycle_detail, "rebuild ctf-os-sandbox:base and run sandbox-gc")
    else:
        add("sandbox-lifecycle", False, "category images missing", "run sandbox/build-images.sh")

    disk = shutil.disk_usage(repo)
    disk_ok = disk.free >= 10 * 1024**3
    add("disk-space", disk_ok, f"{disk.free // 1024**3} GiB free", "free at least 10 GiB")
    memory_bytes = _available_memory()
    add("memory", memory_bytes >= 2 * 1024**3, f"{memory_bytes // 1024**3} GiB available", "free at least 2 GiB RAM")
    add("output-write", _write_probe(repo / "output"), str(repo / "output"), "make repository output/ writable and remove unsafe symlinks")

    skill_files = [
        repo / ".codex/skills/ctf-intake/SKILL.md",
        repo / ".codex/skills/ctf-triage/SKILL.md",
        repo / ".codex/skills/ctf-solve/SKILL.md",
    ]
    playbooks = list((repo / "ctf_os/resources/knowledge/playbooks").glob("*.md"))
    add("skills", all(path.is_file() and not path.is_symlink() for path in skill_files), ", ".join(str(path) for path in skill_files), "restore the tracked skill files")
    add("playbooks", len(playbooks) >= 7, f"{len(playbooks)} files", "restore ctf_os/resources/knowledge/playbooks")
    add("service-runtime", importlib.util.find_spec("ctf_os.service") is not None, "ctf_os.service", "restore the service runtime module")
    add("replay-runtime", importlib.util.find_spec("ctf_os.replay") is not None, "ctf_os.replay", "restore the replay module")

    stale_containers = _run(["docker", "ps", "-aq", "--filter", "label=ctf-os=true"]) if docker.returncode == 0 else subprocess.CompletedProcess([], 1, "", "")
    stale_networks = _run(["docker", "network", "ls", "-q", "--filter", "label=ctf-os=true"]) if docker.returncode == 0 else subprocess.CompletedProcess([], 1, "", "")
    stale_count = len(stale_containers.stdout.split()) + len(stale_networks.stdout.split())
    add(
        "stale-resources", stale_count == 0, f"{stale_count} labeled Docker resources",
        "run sandbox-gc for stale sandboxes; use the matching service-cleanup selector for challenge-service resources",
    )
    return {"ok": all(bool(item["ok"]) for item in checks), "checks": checks}


def _available_memory() -> int:
    try:
        values = (Path("/proc/meminfo").read_text(encoding="ascii").splitlines())
        line = next(line for line in values if line.startswith("MemAvailable:"))
        return int(line.split()[1]) * 1024
    except (OSError, StopIteration, ValueError):
        return 0


def _write_probe(output: Path) -> bool:
    if output.is_symlink():
        return False
    try:
        output.mkdir(parents=True, exist_ok=True)
        probe = output / ".doctor-write-probe"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        return True
    except OSError:
        return False


def _sandbox_lifecycle_probe() -> tuple[bool, str]:
    metadata: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="ctf-os-doctor-") as temporary:
        root = Path(temporary) / "challenge"
        source = root / "input"
        source.mkdir(parents=True)
        (source / "probe").write_text("ok", encoding="ascii")
        try:
            metadata = create(SandboxSpec(
                "doctor", "probe", "smoke", source, root / "workers" / "smoke",
                image="ctf-os-sandbox:base", resource_profile="light",
            ))
            receipt = execute(metadata, ["sh", "-c", "test -r /challenge/probe && test -w /work"], 20)
            cleaned = cleanup(metadata)
            ok = receipt["exit_code"] == 0 and cleaned["removed"] is True
            return ok, "create/exec/final-export/cleanup passed" if ok else f"receipt={receipt}, cleanup={cleaned}"
        except Exception as exc:
            if metadata is not None:
                try:
                    cleanup(metadata)
                except Exception:
                    pass
            return False, str(exc)
