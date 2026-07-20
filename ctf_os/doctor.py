"""Pre-contest infrastructure and immutable image capability checks."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from .delegation import DelegationError, load_templates
from .sandbox.runtime import SandboxSpec, cleanup, create, execute
from .timeouts import TimeoutProfileError, load_timeout_profiles


PROFILES = ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud")
IMAGES = tuple(f"ctf-os-sandbox:{name}" for name in PROFILES)

_COMMON_ENV = (
    "export HOME=/work/home XDG_CONFIG_HOME=/work/home/.config "
    "XDG_CACHE_HOME=/work/home/.cache XDG_RUNTIME_DIR=/work/runtime TMPDIR=/work/tmp "
    "AWS_SHARED_CREDENTIALS_FILE=/work/credentials/aws AWS_CONFIG_FILE=/work/credentials/aws-config "
    "AZURE_CONFIG_DIR=/work/credentials/azure CLOUDSDK_CONFIG=/work/credentials/gcloud "
    "KUBECONFIG=/work/credentials/kubeconfig; "
    "mkdir -p \"$HOME\" \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" "
    "\"$XDG_RUNTIME_DIR\" \"$TMPDIR\" /work/credentials; "
)

PROFILE_PROBES: dict[str, str] = {
    "base": """
command -v python3; command -v jq; command -v rg; command -v objdump; command -v strings; command -v readelf; command -v nmap
python3 -c 'import requests,httpx,bs4,lxml,yaml,rich,numpy,scipy,PIL,networkx,sympy,z3,Crypto,cryptography,capstone,unicorn'
python3 --version; jq --version; rg --version; objdump --version; nmap --version
""",
    "pwn": """
for c in gdb gdb-multiarch qemu-aarch64 qemu-mips qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 patchelf checksec ROPgadget ropper one_gadget; do command -v "$c"; done
python3 -c 'import pwn,angr,unicorn,capstone,keystone,z3'
gdb --version; patchelf --version; checksec --help >/dev/null; ROPgadget --version; ropper --version; one_gadget --version
qemu-aarch64 --version; qemu-mips --version; qemu-system-x86_64 --version
""",
    "web": """
for c in node npm npx corepack php sqlite3 redis-cli psql mysql; do command -v "$c"; done
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
python3 -c 'import flask,fastapi,uvicorn,jwt,requests,httpx,websockets,dns'
node --version; npm --version; php --version; sqlite3 --version
""",
    "rev": """
(command -v r2 || command -v rizin)
for c in gdb gdb-multiarch jadx apktool wasm-objdump upx wasmtime mono qemu-aarch64 qemu-mips qemu-riscv64; do command -v "$c"; done
python3 -c 'import angr,unicorn,capstone,keystone,lief,pefile,elftools'
r2 -v; jadx --version; apktool --version; wasm-objdump --version; upx --version; wasmtime --version
""",
    "crypto": """
for c in sage RsaCtfTool cado-nfs gp gap maxima; do command -v "$c"; done
python3 -c 'import z3,gmpy2,Crypto,fpylll,cysignals,sympy,cryptography,ecdsa'
sage -c 'assert 2^10 == 1024; assert GF(7)(3)^2 == 2'
RsaCtfTool --help >/dev/null; cado-nfs --help >/dev/null; gp --version; gap --version; maxima --version
""",
    "forensic": """
for c in vol mmls fls icat foremost exiftool binwalk tshark tcpdump testdisk photorec dcfldd steghide stegseek zsteg convert tesseract pngcheck ffmpeg sox; do command -v "$c"; done
python3 -c 'import volatility3,scapy,pyshark,oletools,pdfminer,magic,PIL,numpy,scipy,capstone'
vol -h >/dev/null; mmls -V; tshark --version; stegseek --version; zsteg -h >/dev/null; ffmpeg -version; sox --version
""",
    "misc": """
for c in ffmpeg sox convert tesseract tshark binwalk exiftool dot parallel podman zbarimg php lua perl node npm; do command -v "$c"; done
python3 -c 'import torch,sklearn,cv2,pandas,PIL,numpy,scipy,networkx,sympy,z3,scapy,qrcode; assert torch.tensor([2,3]).sum().item() == 5'
ffmpeg -version; sox --version; convert -version; tesseract --version
podman --storage-driver=vfs info --format '{{.Host.Security.Rootless}}' | grep -q true
tar -cf /work/rootfs.tar --files-from /dev/null
podman --storage-driver=vfs import /work/rootfs.tar localhost/ctf-os-smoke:local >/dev/null
podman --storage-driver=vfs image inspect localhost/ctf-os-smoke:local --format '{{.RepoTags}}' | grep -q ctf-os-smoke
""",
    "osint": """
for c in whois dig nslookup host traceroute chromium exiftool convert tesseract ffmpeg yt-dlp git-lfs pdftotext waybackurls; do command -v "$c"; done
python3 -c 'import requests,httpx,bs4,lxml,playwright,PIL,cv2,pandas,whois,dns,geopy,exifread,pdfminer'
chromium --headless --no-sandbox --disable-gpu --dump-dom 'data:text/html,<title>ctf-os</title>' | grep -q ctf-os
""",
    "ai": """
for c in protoc h5dump ncdump dot jupyter; do command -v "$c"; done
python3 - <<'PY'
import numpy as np, onnx, onnxruntime as ort, torch, torchvision
import sklearn, transformers, tokenizers, sentencepiece, safetensors, datasets, joblib, cv2, pandas
from onnx import TensorProto, helper
assert torch.tensor([2,3]).sum().item() == 5
node=helper.make_node('Identity',['x'],['y'])
graph=helper.make_graph([node],'smoke',[helper.make_tensor_value_info('x',TensorProto.FLOAT,[1])],[helper.make_tensor_value_info('y',TensorProto.FLOAT,[1])])
model=helper.make_model(graph,opset_imports=[helper.make_opsetid('',17)],ir_version=9)
session=ort.InferenceSession(model.SerializeToString(),providers=['CPUExecutionProvider'])
assert session.run(None,{'x':np.array([7],dtype=np.float32)})[0][0] == 7
PY
""",
    "cloud": """
for c in aws az gcloud kubectl helm terraform tofu podman skopeo oras cosign trivy syft grype kustomize opa conftest checkov semgrep; do command -v "$c"; done
aws --version; az version; gcloud --version; kubectl version --client=true; helm version --short; terraform version; tofu version
podman --version; skopeo --version; oras version; cosign version; trivy --version; syft version; grype version; opa version; conftest --version; checkov --version; semgrep --version
python3 -c 'import boto3,botocore,google.cloud.storage,google.auth,azure.identity,azure.storage.blob,kubernetes,yaml,requests,httpx,jinja2'
test "${AWS_SHARED_CREDENTIALS_FILE:-/work/credentials/aws}" = /work/credentials/aws
test ! -e "$HOME/.aws/credentials"; test ! -e "$HOME/.azure"; test ! -e "$HOME/.config/gcloud"; test ! -e "$HOME/.kube/config"
""",
}


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def _image_probe(profile: str) -> subprocess.CompletedProcess[str]:
    command = _COMMON_ENV + PROFILE_PROBES[profile]
    argv = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--user", "1001:1001",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--tmpfs", "/work:rw,nosuid,nodev,size=1g,mode=1777",
        "--tmpfs", "/artifacts:rw,nosuid,nodev,size=64m,mode=1777",
    ]
    if profile in {"misc", "cloud"}:
        seccomp = Path(__file__).resolve().parents[1] / "sandbox" / "seccomp-rootless.json"
        argv.extend(["--security-opt", f"seccomp={seccomp}"])
    argv.extend(["--entrypoint", "sh", f"ctf-os-sandbox:{profile}", "-ec", command])
    return _run(argv, timeout=180)


def run_doctor(repo: Path) -> dict[str, object]:
    checks: list[dict[str, object]] = []

    def add(name: str, ok: bool, detail: str, fix: str | None = None) -> None:
        item: dict[str, object] = {"name": name, "ok": ok, "detail": detail}
        if not ok and fix:
            item["fix"] = fix
        checks.append(item)

    ubuntu = _ubuntu_release()
    machine = platform.machine().casefold()
    kernel_release = platform.release().casefold()
    wsl = "microsoft" in kernel_release or bool(os.environ.get("WSL_INTEROP"))
    supported_host = (
        platform.system() == "Linux" and ubuntu
        and machine in {"x86_64", "amd64"} and not wsl
    )
    add(
        "host-platform", bool(supported_host),
        f"system={platform.system()} distribution={'ubuntu' if ubuntu else 'unsupported'} "
        f"machine={platform.machine()} kernel={platform.release()} "
        f"environment={'WSL_UNSUPPORTED' if wsl else 'native'}",
        "use Ubuntu Linux x86_64 for the official competition runtime",
    )
    for executable in ("python3", "uv", "docker"):
        path = shutil.which(executable)
        add(executable, bool(path), path or "not found", f"install {executable} and place it on PATH")
    docker = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    docker_detail = docker.stdout.strip() or docker.stderr.strip()
    failure_kind = _docker_failure_kind(docker_detail)
    socket = Path("/var/run/docker.sock")
    socket_access = docker.returncode == 0 or (
        socket.exists() and os.access(socket, os.R_OK | os.W_OK)
    )
    add(
        "docker-socket-access", socket_access,
        "daemon access verified" if docker.returncode == 0 else (
            f"{socket}: current user lacks read/write access"
            if socket.exists() and not socket_access else f"{socket}: unavailable"
        ),
        "grant the current user Docker socket access; CTF-OS never invokes sudo",
    )
    add(
        "docker-daemon", docker.returncode == 0,
        docker_detail if docker.returncode == 0 else failure_kind,
        "start Docker Engine or correct the reported daemon/socket error",
    )
    compose = _run(["docker", "compose", "version", "--short"])
    add("docker-compose", compose.returncode == 0, compose.stdout.strip() or compose.stderr.strip(), "install Docker Compose v2")
    build_command = _run(["docker", "build", "--help"])
    run_command = _run(["docker", "run", "--help"])
    add("docker-build-command", build_command.returncode == 0, "available" if build_command.returncode == 0 else build_command.stderr.strip(), "install a Docker CLI with docker build")
    add("docker-run-command", run_command.returncode == 0, "available" if run_command.returncode == 0 else run_command.stderr.strip(), "install a Docker CLI with docker run")

    if docker.returncode == 0:
        for profile, image in zip(PROFILES, IMAGES, strict=True):
            present = _run(["docker", "image", "inspect", image])
            add(f"image-{profile}", present.returncode == 0, "tag present" if present.returncode == 0 else present.stderr.strip(), f"run sandbox/build-images.sh {profile}")
            if present.returncode == 0:
                smoke = _image_probe(profile)
                streams = "\n".join(part.strip() for part in (smoke.stdout, smoke.stderr) if part.strip())
                detail = streams or "all required binary/import/operation probes passed"
                add(f"image-{profile}-tools", smoke.returncode == 0, detail[-8_000:], f"rebuild ctf-os-sandbox:{profile}")
        if all(_run(["docker", "image", "inspect", image]).returncode == 0 for image in IMAGES):
            lifecycle_ok, lifecycle_detail = _sandbox_lifecycle_probe()
            add("sandbox-lifecycle", lifecycle_ok, lifecycle_detail, "rebuild ctf-os-sandbox:base and run sandbox-gc")
        else:
            add("sandbox-lifecycle", False, "one or more category images are missing", "run sandbox/build-images.sh")
    else:
        for profile in PROFILES:
            add(f"image-{profile}", False, "Docker daemon unavailable", f"run sandbox/build-images.sh {profile}")
        add("sandbox-lifecycle", False, "Docker daemon unavailable", "start Docker and run sandbox/build-images.sh")

    disk = shutil.disk_usage(repo)
    add("disk-space", disk.free >= 20 * 1024**3, f"{disk.free // 1024**3} GiB free", "free at least 20 GiB")
    if docker.returncode == 0:
        docker_root_result = _run(["docker", "info", "--format", "{{.DockerRootDir}}"])
        docker_root = Path(docker_root_result.stdout.strip()) if docker_root_result.returncode == 0 and docker_root_result.stdout.strip() else None
        try:
            docker_disk = shutil.disk_usage(docker_root) if docker_root else None
        except OSError:
            docker_disk = None
        add(
            "docker-data-root-space", bool(docker_disk and docker_disk.free >= 20 * 1024**3),
            f"{docker_disk.free // 1024**3} GiB free at {docker_root}" if docker_disk else "Docker data-root cannot be inspected",
            "free at least 20 GiB in Docker data-root",
        )
    memory_bytes = _available_memory()
    add("memory", memory_bytes >= 2 * 1024**3, f"{memory_bytes // 1024**3} GiB available", "free at least 2 GiB RAM")
    add("output-write", _write_probe(repo / "output"), str(repo / "output"), "make repository output/ writable and remove unsafe symlinks")

    skill_files = [repo / f".codex/skills/{name}/SKILL.md" for name in ("ctf-intake", "ctf-triage", "ctf-solve")]
    playbooks = list((repo / "ctf_os/resources/knowledge/playbooks").glob("*.md"))
    add("skills", all(path.is_file() and not path.is_symlink() for path in skill_files), ", ".join(str(path) for path in skill_files), "restore the tracked skill files")
    add("playbooks", len(playbooks) >= 9, f"{len(playbooks)} files", "restore all nine category playbooks")
    template_path = repo / "ctf_os/resources/delegation-templates.yaml"
    try:
        templates = load_templates(template_path)
        template_ok, template_detail = len(templates) >= 9, f"{len(templates)} categories"
    except (DelegationError, OSError) as exc:
        template_ok, template_detail = False, str(exc)
    add("delegation-templates", template_ok, template_detail, "restore the validated delegation template resource")
    try:
        timeout_profiles = load_timeout_profiles(repo / "ctf_os/resources/timeout-profiles.yaml")
        timeout_ok, timeout_detail = len(timeout_profiles) == 9, f"{len(timeout_profiles)} profiles"
    except (TimeoutProfileError, OSError) as exc:
        timeout_ok, timeout_detail = False, str(exc)
    add("timeout-profiles", timeout_ok, timeout_detail, "restore the validated timeout profile resource")
    add("service-runtime", importlib.util.find_spec("ctf_os.service") is not None, "ctf_os.service", "restore the service runtime module")
    add("replay-runtime", importlib.util.find_spec("ctf_os.replay") is not None, "ctf_os.replay", "restore the replay module")

    # Doctor owns sandbox health, not another active solve's shared service.
    # Count only stopped worker sandboxes that sandbox-gc can safely remove;
    # active race sandboxes and exact-label service lifecycles are not stale.
    stale_sandboxes = _run([
        "docker", "ps", "-aq", "--filter", "label=ctf-os=true",
        "--filter", "label=ctf-os.kind=sandbox", "--filter", "status=exited",
    ]) if docker.returncode == 0 else subprocess.CompletedProcess([], 1, "", "")
    stale_count = len(stale_sandboxes.stdout.split())
    add("stale-resources", stale_count == 0, f"{stale_count} stopped sandbox resources", "run sandbox-gc for stopped sandboxes")
    nvidia = shutil.which("nvidia-smi")
    add(
        "gpu-optional", True,
        "NVIDIA tooling detected; GPU-required requests perform runtime validation"
        if nvidia else "not installed; CPU profiles including AI remain supported",
    )
    return {"ok": all(bool(item["ok"]) for item in checks), "checks": checks}


def _ubuntu_release() -> bool:
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        return values.get("ID", "").casefold() == "ubuntu"
    except OSError:
        return False


def _docker_failure_kind(detail: str) -> str:
    lowered = detail.casefold()
    if "permission denied" in lowered:
        return f"SOCKET_PERMISSION_DENIED: {detail}"
    if "cannot connect" in lowered or "connection refused" in lowered:
        return f"DAEMON_STOPPED_OR_UNREACHABLE: {detail}"
    if not shutil.which("docker"):
        return "DOCKER_CLI_MISSING"
    return f"DAEMON_RESPONSE_ERROR: {detail or 'no daemon response'}"


def _available_memory() -> int:
    try:
        line = next(line for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines() if line.startswith("MemAvailable:"))
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
            metadata = create(SandboxSpec("doctor", "probe", "smoke", source, root / "workers" / "smoke", image="ctf-os-sandbox:base", resource_profile="light"))
            receipt = execute(metadata, ["sh", "-c", "test -r /challenge/probe && ! test -w /challenge/probe && test -w /work && test -w /artifacts && test $(id -u) = 1001"], 20)
            cleaned = cleanup(metadata)
            ok = receipt["exit_code"] == 0 and cleaned["removed"] is True
            return ok, "non-root create/ro-challenge/rw-work/rw-artifacts/exec/export/cleanup passed" if ok else f"receipt={receipt}, cleanup={cleaned}"
        except Exception as exc:
            cleanup_error = ""
            if metadata is not None:
                try:
                    cleanup(metadata)
                except Exception as cleanup_exc:
                    cleanup_error = f"; cleanup also failed: {cleanup_exc}"
            return False, f"{exc}{cleanup_error}"
