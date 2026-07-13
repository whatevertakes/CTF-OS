import os
from pathlib import Path
import subprocess

import pytest

from ctf_os.sandbox.runtime import SandboxSpec, cleanup, create, execute
from ctf_os.service import ServiceSpec, service_build, service_cleanup, service_start


pytestmark = pytest.mark.skipif(os.environ.get("CTF_OS_LIVE_DOCKER") != "1", reason="live Docker opt-in")


def _assert_missing(kind: str, name: str) -> None:
    assert subprocess.run(["docker", kind, "inspect", name], capture_output=True).returncode != 0


def test_live_dockerfile_service_connects_from_scoped_sandbox_and_cleans(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "server.py").write_text(
        "import socket\ns=socket.socket();s.bind(('0.0.0.0',31337));s.listen()\n"
        "while True:\n c,_=s.accept();c.sendall(b'LIVE{pwn-service}\\n');c.close()\n"
    )
    (source / "Dockerfile").write_text(
        "FROM python:3.12-alpine\nCOPY server.py /server.py\nEXPOSE 31337\nCMD [\"python3\",\"/server.py\"]\n"
    )
    workspace = tmp_path / "output" / "pwn"
    plan = {
        "kind": "dockerfile", "safe_to_start": True, "build_context": ".", "dockerfile": "Dockerfile",
        "services": [{"name": "chall", "port": 31337, "internal_target": "chall:31337"}],
    }
    service = ServiceSpec("live", "pwn123", source, workspace, plan, build_timeout=300, start_timeout=30)
    service_build(service)
    service_start(service)
    branch = workspace / "workers" / "connect"
    sandbox = create(SandboxSpec(
        "live", "pwn123", "connect", source, branch, image="ctf-os-sandbox:base",
        resource_profile="light", service_network=service.network, local_endpoints=("chall:31337",),
    ))
    try:
        receipt = execute(sandbox, ["python3", "-c", "import socket;s=socket.create_connection(('chall',31337));print(s.recv(100).decode().strip())"], 20)
        assert receipt["stdout"].strip() == "LIVE{pwn-service}"
    finally:
        cleanup(sandbox)
        service_cleanup(service)
    _assert_missing("container", sandbox["name"])
    _assert_missing("network", service.network)


def test_live_compose_web_service_connects_without_host_port_and_cleans(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "index.html").write_text("LIVE{web-compose}\n")
    (source / "Dockerfile").write_text(
        "FROM python:3.12-alpine\nWORKDIR /srv\nCOPY index.html .\nEXPOSE 8080\nCMD [\"python3\",\"-m\",\"http.server\",\"8080\",\"--bind\",\"0.0.0.0\"]\n"
    )
    (source / "compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports: [\"18080:8080\"]\n"
    )
    workspace = tmp_path / "output" / "web"
    plan = {
        "kind": "compose", "safe_to_start": True, "compose_file": "compose.yml",
        "services": [{"name": "web", "port": 8080, "internal_target": "http://web:8080"}],
    }
    service = ServiceSpec("live", "web123", source, workspace, plan, build_timeout=300, start_timeout=30)
    service_build(service)
    started = service_start(service)
    branch = workspace / "workers" / "connect"
    sandbox = create(SandboxSpec(
        "live", "web123", "connect", source, branch, image="ctf-os-sandbox:base",
        resource_profile="light", service_network=service.network, local_endpoints=("http://web:8080",),
    ))
    try:
        receipt = execute(sandbox, ["curl", "--fail", "--silent", "http://web:8080"], 20)
        assert receipt["stdout"].strip() == "LIVE{web-compose}"
        published = subprocess.run(["docker", "port", next(item["name"] for item in started["containers"])], capture_output=True, text=True)
        assert published.stdout.strip() == ""
    finally:
        cleanup(sandbox)
        service_cleanup(service)
    _assert_missing("container", sandbox["name"])
    _assert_missing("network", service.network)


def test_live_problem_networks_do_not_cross_connect(tmp_path: Path) -> None:
    services: list[ServiceSpec] = []
    sandboxes: list[dict[str, object]] = []
    try:
        for challenge, alias, port in (("one123", "one", 31001), ("two123", "two", 31002)):
            source = tmp_path / challenge / "input"
            source.mkdir(parents=True)
            (source / "server.py").write_text(
                f"import socket\ns=socket.socket();s.bind(('0.0.0.0',{port}));s.listen()\n"
                "while True:\n c,_=s.accept();c.sendall(b'ok\\n');c.close()\n"
            )
            (source / "Dockerfile").write_text(
                f"FROM python:3.12-alpine\nCOPY server.py /server.py\nEXPOSE {port}\nCMD [\"python3\",\"/server.py\"]\n"
            )
            service = ServiceSpec(
                "isolation", challenge, source, tmp_path / challenge / "output",
                {
                    "kind": "dockerfile", "safe_to_start": True,
                    "build_context": ".", "dockerfile": "Dockerfile",
                    "services": [{"name": alias, "port": port, "internal_target": f"{alias}:{port}"}],
                },
                build_timeout=300, start_timeout=30,
            )
            services.append(service)
            service_build(service)
            service_start(service)

        first = services[0]
        branch = first.workspace / "workers" / "isolation"
        sandbox = create(SandboxSpec(
            "isolation", "one123", "isolation", first.source, branch,
            image="ctf-os-sandbox:base", resource_profile="light",
            service_network=first.network, local_endpoints=("one:31001",),
        ))
        sandboxes.append(sandbox)
        own = execute(sandbox, ["python3", "-c", "import socket;s=socket.create_connection(('one',31001));print(s.recv(8).decode().strip())"], 20)
        crossed = execute(sandbox, ["python3", "-c", "import socket;socket.getaddrinfo('two',31002)"], 20)
        assert own["stdout"].strip() == "ok"
        assert crossed["exit_code"] != 0
    finally:
        for sandbox in reversed(sandboxes):
            cleanup(sandbox)
        for service in reversed(services):
            service_cleanup(service)
    for service in services:
        _assert_missing("network", service.network)
