from __future__ import annotations

import json
from pathlib import Path
import subprocess
import zipfile

import pytest

from ctf_os.archive import ArchiveError, extract_archive
from ctf_os.preflight import detect_service
from ctf_os.sandbox.network import NetworkPolicyError, ResolvedTarget, Target, parse_remotes
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv
from ctf_os.sandbox.session import (
    SessionError, list_tools, open_session, read as session_read, tool_help,
)
from ctf_os.service import ServiceActor, ServiceError, ServiceSpec, prepare_service

from conftest import fake_sandbox, make_race


def test_sandbox_has_read_only_input_private_writable_paths_and_no_host_credentials(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    target = ResolvedTarget(Target("nc ctf.example 31337", "ctf.example", 31337, "nc"), "203.0.113.10")
    spec = SandboxSpec(
        run_id="run-1", contest_slug="demo", challenge_id="challenge1", category="pwn",
        lane_id="root", source=source, lane_root=tmp_path / "workers" / "root",
        input_fingerprint="0" * 64, image="ctf-os-sandbox:pwn", targets=(target,),
    )
    for name in ("work", "evidence", "artifacts", "context"):
        (spec.lane_root / name).mkdir(parents=True, exist_ok=True)
    argv = build_run_argv(spec)
    joined = " ".join(argv)
    assert f"src={source.resolve()},dst=/challenge,readonly" in joined
    assert "dst=/work" in joined and "dst=/evidence" in joined and "dst=/artifacts" in joined
    assert "/var/run/docker.sock" not in joined
    for forbidden in (".ssh", "kubeconfig", ".aws", "chrome", "host.docker.internal"):
        assert forbidden not in joined.casefold()
    assert "--network bridge" in joined
    assert "CTF_OS_ALLOWED_ENDPOINTS_JSON" in joined


def test_metadata_gateways_private_networks_and_undeclared_targets_are_rejected() -> None:
    for value in ("169.254.169.254:80", "172.17.0.1:80", "localhost:80", "10.0.0.5:1234"):
        with pytest.raises(NetworkPolicyError):
            parse_remotes([value])
    declared = parse_remotes([{"host": "10.0.0.5", "port": 31337, "protocol": "tcp", "organizer_declared": True}])
    assert declared[0].organizer_declared is True


def test_archive_traversal_and_links_never_enter_prepared_input(tmp_path: Path) -> None:
    archive = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape", "bad")
    destination = tmp_path / "prepared"
    destination.mkdir()
    with pytest.raises(ArchiveError, match="traversal"):
        extract_archive(archive, destination)
    assert not (tmp_path / "escape").exists()


def test_dangerous_compose_is_blocked_before_service_lifecycle(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: demo\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("Docker socket" in reason for reason in plan["review_reasons"])


def test_compose_build_context_cannot_escape_prepared_input(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    build: ../../\n    expose: [8000]\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("build context escapes" in reason for reason in plan["review_reasons"])


def test_dockerfile_without_declared_port_is_not_misclassified_as_a_service(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "Dockerfile").write_text("FROM scratch\nCOPY chall /chall\n", encoding="utf-8")
    plan = detect_service(input_root, "rev")
    assert plan["kind"] == "none"
    assert plan["safe"] is True


def test_compose_override_resets_host_ports_and_networks(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: ctf-os-sandbox:base\n    ports: ['127.0.0.1:18000:8000']\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    for path in input_root.rglob("*"):
        path.chmod(0o444 if path.is_file() else 0o555)
    input_root.chmod(0o555)
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if "ps" in argv and "--status" in argv:
            return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    spec = ServiceSpec(
        run_id="run-compose", challenge_id="challenge1", source=input_root,
        run_root=tmp_path / "run", plan=plan,
    )
    metadata = prepare_service(spec, actor=ServiceActor("root", "root"), runner=runner)
    override = Path(metadata["runtime"]["compose_files"][1]).read_text(encoding="utf-8")
    assert "ports: !reset []" in override
    assert "networks: !reset" in override
    assert any(argv[1:3] == ["network", "create"] and "--internal" in argv for argv in calls)
    compose_up = next(argv for argv in calls if "up" in argv)
    assert compose_up[-2:] == ["--pull", "never"]


def test_only_root_can_change_service_lifecycle(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    spec = ServiceSpec(
        run_id="run-123", challenge_id="challenge1", source=source, run_root=tmp_path / "run",
        plan={"kind": "dockerfile", "safe": True, "source": "Dockerfile", "context": ".", "services": []},
    )
    with pytest.raises(ServiceError, match="only Root"):
        prepare_service(spec, actor=ServiceActor("lane-1", "child"))


def test_persistent_session_is_category_bounded_and_reads_receipted_output(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if "python3" in argv and "-c" in argv:
            return subprocess.CompletedProcess(argv, 0, "gdb output\n", " 11\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    state = open_session(
        metadata, session_id="dbg-main", kind="debugger", command=["gdb", "-q", "/challenge/chall"], runner=runner
    )
    assert state["status"] == "RUNNING"
    receipt = session_read(metadata, session_id="dbg-main", runner=runner)
    assert receipt["observed_output"] == "gdb output\n"
    assert (run / "workers" / "root" / "logs" / f"{receipt['receipt_id']}.json").is_file()
    assert list_tools("pwn")["tools"]
    assert "gdb" in tool_help("pwn", "gdb")["hint"]


def test_remote_session_requires_exact_declared_identity(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="web")
    metadata = fake_sandbox(run, challenge, "root")
    metadata["target_identities"] = ["nc ctf.example 31337"]
    with pytest.raises(SessionError, match="not declared"):
        open_session(
            metadata, session_id="remote-one", kind="remote", command=["nc", "ctf.example", "31337"],
            target_identity="nc other.example 31337",
        )
