#!/usr/bin/env python3
"""Build and exercise the benchmark-critical tactical Docker profiles."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import time

from ctf_os.artifact_writer import ArtifactWriter
from ctf_os.sandbox.broker import send_broker_request
from ctf_os.sandbox.container import SandboxScope, SandboxSpec
from ctf_os.sandbox.docker_cli import DockerCli
from ctf_os.sandbox.pool import DockerSandboxPool
from ctf_os.tactical_engine.strategies import StrategyExecutor


ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "base": ("fast_recon", ("file", "strings", "readelf", "objdump", "jq", "python3")),
    "pwn": ("dynamic_analysis", ("gdb", "patchelf", "pwninit", "checksec", "ROPgadget", "python3")),
    "web": ("protocol_replay", ("curl", "sqlmap", "nuclei", "python3")),
    "forensics": ("artifact_recovery", ("tshark", "foremost", "binwalk", "exiftool", "file")),
}


def _run(argv: list[str], *, timeout: float = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)


def _build(profile: str) -> dict[str, object]:
    image = f"ctf-os-{profile}:latest"
    started = time.monotonic()
    result = _run([
        "docker", "build", "--pull=false", "-f", str(ROOT / "sandbox/Dockerfile.profiles"),
        "--target", profile, "-t", image, str(ROOT),
    ], timeout=1800)
    return {
        "image": image, "ok": result.returncode == 0,
        "elapsed_sec": time.monotonic() - started,
        "error": (result.stderr or result.stdout)[-1000:] if result.returncode else None,
    }


def _smoke(profile: str, image: str, root: Path) -> dict[str, object]:
    strategy, tools = PROFILES[profile]
    workspace = root / profile / "workspace"
    workspace.mkdir(parents=True)
    workspace.chmod(0o755)
    (workspace / "fixture.txt").write_text("profile smoke\n", encoding="utf-8")
    staging = ArtifactWriter(root / "output" / "team" / "member", "Profile Smoke").create_attempt_staging()
    attempt_id = f"profile-{profile}"
    scope = SandboxScope("team", "member", "Profile Smoke", profile, f"challenge-{profile}", f"profile:{profile}")
    docker = DockerCli()
    pool = DockerSandboxPool(
        scope=scope, workspace_root=root, output_root=root / "output", docker=docker, max_containers=1,
    )
    spec = SandboxSpec(
        scope=scope, attempt_id=attempt_id, workspace=workspace,
        workdir=staging.workdir, artifacts=staging.artifacts, image=image,
        memory="256m", cpus=0.5, pids_limit=64,
    )
    container = pool.precreate(spec)
    broker = pool.broker(attempt_id)
    assert broker is not None
    versions: dict[str, str] = {}
    try:
        for tool in tools:
            command = (tool, "--version")
            if tool == "python3":
                module = "pwn" if profile == "pwn" else "websockets" if profile == "web" else ""
                command = (tool, "-c", f"import {module}; print('python modules ok')") if module else (tool, "--version")
            elif tool in {"checksec", "ROPgadget", "binwalk"}:
                command = (tool, "--help")
            elif tool == "foremost":
                command = (tool, "-h")
            elif tool == "exiftool":
                command = (tool, "-ver")
            result = docker.exec(["docker", "exec", "--user", "ctf", "-w", "/work", container.name, *command], timeout_sec=30)
            version_lines = [line for line in (result.stdout or result.stderr).splitlines() if line.strip()]
            versions[tool] = (version_lines or ["available (smoke exit 0)"])[0][:200]
            if result.returncode != 0 or "not found" in (result.stderr or "").casefold():
                raise RuntimeError(f"{tool} smoke failed: {result.stderr or result.stdout}")
        bootstrap = StrategyExecutor().bootstrap(strategy, staging.workdir, which=lambda name: f"/usr/bin/{name}")
        write = send_broker_request(
            broker.socket_path, attempt_id=attempt_id, token=broker.token,
            argv=("python3", "-c", "open('/work/profile.txt','w').write('work');open('/artifacts/result.txt','w').write('artifact');print(open('/work/profile.txt').read()+':'+open('/artifacts/result.txt').read())"),
        )
        if write.returncode != 0:
            raise RuntimeError(f"broker write smoke failed: {write.stderr}")
        inspected = _run(["docker", "inspect", container.name], timeout=30)
        details = json.loads(inspected.stdout)[0]
        workspace_mount = next(item for item in details["Mounts"] if item["Destination"] == "/workspace")
        timeout_result = docker.exec(
            ["docker", "exec", "--user", "ctf", container.name, "sleep", "5"], timeout_sec=0.2,
        )
        result = pool.release(attempt_id, remove=True)
        absent = _run(["docker", "inspect", container.name], timeout=30).returncode != 0
        return {
            "ok": bool(write.returncode == 0 and result and result.ok and absent),
            "versions": versions,
            "harness": strategy, "harness_manifest": bootstrap.manifest_path.name,
            "read_only_workspace": workspace_mount["RW"] is False,
            "mount_read_write": write.stdout.strip() == "work:artifact",
            "timeout_enforced": timeout_result.timed_out,
            "memory_bytes": details["HostConfig"]["Memory"],
            "nano_cpus": details["HostConfig"]["NanoCpus"],
            "pids_limit": details["HostConfig"]["PidsLimit"],
            "network_mode": details["HostConfig"]["NetworkMode"],
            "cleanup_ok": absent,
        }
    finally:
        if pool.get(attempt_id) is not None:
            pool.release(attempt_id, remove=True)
        ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", action="append", choices=tuple(PROFILES))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/results/profile-smoke.json")
    args = parser.parse_args()
    selected = args.profile or list(PROFILES)
    report: dict[str, object] = {"created_at": datetime.now(timezone.utc).isoformat(), "profiles": {}}
    failures = 0
    with tempfile.TemporaryDirectory(prefix="ctf-os-profile-smoke-") as temporary:
        for profile in selected:
            built = {"image": f"ctf-os-{profile}:latest", "ok": True, "skipped": True} if args.skip_build else _build(profile)
            item: dict[str, object] = {"build": built}
            if built["ok"]:
                try:
                    item["smoke"] = _smoke(profile, str(built["image"]), Path(temporary))
                except Exception as exc:
                    item["smoke"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if not built["ok"] or not item.get("smoke", {}).get("ok"):  # type: ignore[union-attr]
                failures += 1
            report["profiles"][profile] = item  # type: ignore[index]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
