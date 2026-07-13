from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from ctf_os.service import (
    ServiceError,
    ServiceSpec,
    attach_analysis_sandbox,
    service_build,
    service_cleanup,
    service_plan,
    service_start,
)


class FakeDocker:
    def __init__(self, compose: dict[str, object] | None = None) -> None:
        self.compose = compose
        self.calls: list[tuple[list[str], int]] = []
        self.network_exists = False
        self.containers: dict[str, dict[str, str]] = {}

    def __call__(self, argv, timeout: int) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        self.calls.append((args, timeout))
        if "compose" in args and "config" in args:
            return self.done(args, stdout=json.dumps(self.compose or {}))
        if args[1:3] == ["network", "inspect"]:
            if not self.network_exists:
                return self.done(args, 1, stderr="Error: No such network")
            labels = _labels("demo", "abc")
            return self.done(args, stdout=json.dumps({"Name": args[3], "Internal": True, "Labels": labels, "Containers": {}}))
        if args[1:3] == ["network", "create"]:
            self.network_exists = True
            return self.done(args, stdout=args[-1])
        if args[1] == "build":
            return self.done(args, stdout="built")
        if "compose" in args and "build" in args:
            return self.done(args, stdout="built")
        if args[1] == "run":
            name = args[args.index("--name") + 1]
            self.containers[name] = _labels("demo", "abc")
            return self.done(args, stdout="container-id")
        if "compose" in args and "up" in args:
            self.containers["compose-web-1"] = _labels("demo", "abc")
            return self.done(args)
        if args[1] == "ps":
            output = "\n".join(json.dumps({"ID": "id", "Names": name, "State": "running", "Status": "Up"}) for name in self.containers)
            return self.done(args, stdout=output)
        if args[1] == "logs":
            return self.done(args, stdout="service ready\n")
        if args[1] == "inspect" and ".Config.Labels" in args[-1]:
            labels = self.containers.get(args[2])
            return self.done(args, 0 if labels else 1, stdout=json.dumps(labels) if labels else "", stderr="" if labels else "No such object")
        if args[1:3] == ["network", "connect"]:
            return self.done(args)
        if args[1] in {"volume", "image"} and "ls" in args:
            return self.done(args)
        if args[1:3] == ["network", "rm"]:
            self.network_exists = False
            return self.done(args)
        if args[1] == "rm":
            self.containers.pop(args[-1], None)
            return self.done(args)
        if args[1] == "stop":
            return self.done(args)
        raise AssertionError(f"unexpected Docker call: {args}")

    @staticmethod
    def done(argv: list[str], code: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


def _labels(contest: str, challenge: str) -> dict[str, str]:
    # Scope is deterministic but intentionally obtained via a temporary spec in tests that need it.
    raw = f"{contest}-{challenge}"
    import hashlib
    return {
        "ctf-os": "true", "ctf-os.kind": "challenge-service",
        "ctf-os.contest": contest, "ctf-os.challenge_id": challenge,
        "ctf-os.service_scope": f"{raw}-{hashlib.sha256(raw.encode()).hexdigest()[:10]}",
    }


def _spec(tmp_path: Path, plan: dict[str, object]) -> ServiceSpec:
    source = tmp_path / "input"
    source.mkdir(exist_ok=True)
    workspace = tmp_path / "output" / "challenge"
    workspace.mkdir(parents=True, exist_ok=True)
    return ServiceSpec("demo", "abc", source, workspace, plan, build_timeout=60, start_timeout=20)


def test_dockerfile_build_and_start_are_private_limited_and_labelled(tmp_path: Path) -> None:
    spec = _spec(tmp_path, {"kind": "dockerfile", "build_context": ".", "dockerfile": "Dockerfile", "services": [{"name": "chall", "port": 31337}]})
    (spec.source / "Dockerfile").write_text("FROM scratch\n")
    fake = FakeDocker()

    built = service_build(spec, runner=fake)
    started = service_start(spec, runner=fake)

    build = next(call for call, _ in fake.calls if call[1] == "build")
    run = next(call for call, _ in fake.calls if call[1] == "run")
    network = next(call for call, _ in fake.calls if call[1:3] == ["network", "create"])
    assert built["status"] == "BUILT" and started["status"] == "RUNNING"
    assert "--internal" in network
    assert ["--network", spec.network] == run[run.index("--network"):run.index("--network") + 2]
    assert ["--network-alias", "chall"] == run[run.index("--network-alias"):run.index("--network-alias") + 2]
    assert "--memory" in run and "--cpus" in run and "--pids-limit" in run
    assert "--label" in build and "--label" in run
    assert not any("docker.sock" in item for item in run)
    assert (spec.runtime_root / "service.log").is_file()
    assert any(call[1] == "logs" for call, _ in fake.calls)


def test_runtime_accepts_intake_nested_dockerfile_shape(tmp_path: Path) -> None:
    spec = _spec(tmp_path, {
        "kind": "dockerfile", "safe_to_start": True,
        "compose_files": [],
        "services": [{
            "name": "binary", "build_context": ".", "dockerfile": "Dockerfile",
            "build_args": ["PORT=31337", "UNSET"], "environment": ["PORT=31337"],
        }],
    })
    (spec.source / "Dockerfile").write_text("FROM scratch\n")
    fake = FakeDocker()

    service_build(spec, runner=fake)
    service_start(spec, runner=fake)

    build = next(call for call, _ in fake.calls if call[1] == "build")
    run = next(call for call, _ in fake.calls if call[1] == "run")
    assert "PORT=31337" in build and "UNSET" not in build
    assert run[run.index("--network-alias") + 1] == "binary"


def test_compose_override_removes_host_ports_and_forces_external_private_network(tmp_path: Path) -> None:
    spec = _spec(tmp_path, {"kind": "compose", "compose_files": ["compose.yml"], "services": [{"name": "web", "port": 8080}]})
    (spec.source / "compose.yml").write_text("services:\n  web:\n    image: nginx\n    ports: ['8080:80']\n")
    compose = {"services": {"web": {"image": "nginx", "ports": [{"published": "8080", "target": 80}], "networks": {"default": None}}}}
    fake = FakeDocker(compose)

    service_start(spec, runner=fake)

    override = (spec.runtime_root / "compose.ctf-os.override.yml").read_text()
    assert "ports: !reset []" in override
    assert "networks: !override" in override
    assert "external: true" in override and spec.network in override
    up = next(call for call, _ in fake.calls if "compose" in call and "up" in call)
    assert "--wait" in up and "--no-build" in up


@pytest.mark.parametrize(
    "service, expected",
    [
        ({"image": "x", "privileged": True}, "privileged=true"),
        ({"image": "x", "network_mode": "host"}, "network_mode=host"),
        ({"image": "x", "pid": "host"}, "pid=host"),
        ({"image": "x", "ipc": "host"}, "ipc=host"),
        ({"image": "x", "devices": ["/dev/kvm:/dev/kvm"]}, "host devices"),
        ({"image": "x", "cap_add": ["SYS_ADMIN"]}, "broad cap_add"),
        ({"image": "x", "volumes": [{"type": "bind", "source": "/", "target": "/host"}]}, "escapes"),
        ({"image": "x", "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, "Docker socket"),
        ({"image": "x", "networks": {"outside": None}}, "custom networks"),
    ],
)
def test_unsafe_compose_is_needs_review_and_never_started(tmp_path: Path, service: dict[str, object], expected: str) -> None:
    spec = _spec(tmp_path, {"kind": "compose", "compose_file": "compose.yml"})
    (spec.source / "compose.yml").write_text("services: {}\n")
    fake = FakeDocker({"services": {"web": service}})

    checked = service_plan(spec, runner=fake)
    assert checked["safe_to_start"] is False
    assert expected in " ".join(checked["review_reasons"])
    with pytest.raises(ServiceError, match="NEEDS_REVIEW"):
        service_start(spec, runner=fake)
    assert not any(call[1:3] == ["network", "create"] or "up" in call for call, _ in fake.calls)


def test_build_context_and_dockerfile_cannot_escape_challenge(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM scratch\n")
    spec = _spec(tmp_path, {"kind": "dockerfile", "build_context": str(outside), "dockerfile": "Dockerfile"})

    with pytest.raises(ServiceError, match="escapes"):
        service_plan(spec)


def test_cleanup_uses_all_exact_labels_and_does_not_enumerate_global_resources(tmp_path: Path) -> None:
    spec = _spec(tmp_path, {"kind": "dockerfile", "build_context": ".", "dockerfile": "Dockerfile"})
    (spec.source / "Dockerfile").write_text("FROM scratch\n")
    fake = FakeDocker()
    service_start(spec, runner=fake)

    result = service_cleanup(spec, runner=fake)

    assert result["removed"]["network"] is True
    listing = [call for call, _ in fake.calls if call[1] == "ps"][-1]
    assert listing.count("--filter") == len(spec.labels)
    assert all(f"label={key}={value}" in listing for key, value in spec.labels.items())
    assert not any(call[:3] == ["docker", "system", "prune"] for call, _ in fake.calls)
    assert fake.containers == {} and fake.network_exists is False


def test_attach_rejects_cross_challenge_sandbox_before_docker_mutation(tmp_path: Path) -> None:
    spec = _spec(tmp_path, {"kind": "dockerfile", "build_context": ".", "dockerfile": "Dockerfile"})
    fake = FakeDocker()
    sandbox = {"name": "ctf-os-demo-other-branch-123", "labels": {"ctf-os": "true", "ctf-os.contest": "demo", "ctf-os.challenge_id": "other"}}

    with pytest.raises(ServiceError, match="do not match"):
        attach_analysis_sandbox(spec, sandbox, runner=fake)
    assert fake.calls == []
