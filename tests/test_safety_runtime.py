from __future__ import annotations

from dataclasses import replace
from io import StringIO
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
from threading import Thread
from threading import Event
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
import yaml

from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.artifact_writer import AttemptStaging
from ctf_os.intake import IntakeError, ZipExtractionLimits, extract_zip_safely
from ctf_os.sandbox.broker import (
    AttemptCommandBroker,
    BrokerError,
    MAX_BROKER_MESSAGE_BYTES,
    create_ctf_exec_helper,
    send_broker_request,
)
from ctf_os.sandbox.container import SandboxScope, SandboxSpec, build_docker_exec_argv, build_docker_run_argv
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from ctf_os.sandbox.network_policy import RemotePolicyError, parse_remote_endpoints, resolve_remote_endpoints
from ctf_os.sandbox.pool import DockerSandboxPool, build_cleanup_filters
from ctf_os.solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from ctf_os.model_routing import ModelRouter


def _router() -> ModelRouter:
    return ModelRouter.from_mapping({
        "model_profiles": {"d": {"model": "gpt-5.6-terra", "reasoning_effort": "high"}},
        "default_roles": {"default": "d", "recon": "d", "exploit": "d", "source": "d", "fallback": "d"},
    })


def _spec(tmp_path: Path, *, staging: AttemptStaging, endpoints=()) -> SandboxSpec:
    scope = SandboxScope("team", "member", "Demo", "login")
    return SandboxSpec(
        scope=scope,
        attempt_id="attempt-a",
        workspace=tmp_path / "incoming" / "login",
        workdir=staging.workdir,
        artifacts=staging.artifacts,
        endpoints=endpoints,
    )


def test_production_codex_argv_is_strict_profiled_and_filesystem_ipc_only(sterile_staging_factory) -> None:
    backend = CodexCliBackend(model_router=_router())
    staging = sterile_staging_factory()
    socket_path = staging.workdir / ".ctf-os-broker"
    socket_path.mkdir(mode=0o700)
    argv = backend.build_exec_argv(CodexExecRequest(
        workdir=staging.workdir, prompt="solve", broker_socket=socket_path,
    ))
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv
    assert "--sandbox" not in argv
    assert {"--strict-config", "--ignore-user-config", "--ignore-rules"}.issubset(argv)
    assert 'approval_policy="never"' in argv
    assert 'default_permissions="ctf_os_attempt"' in argv
    policy = next(item for item in argv if item.startswith("permissions.ctf_os_attempt="))
    assert f'"{staging.workdir}"=true' in policy
    assert "network={enabled=false" in policy
    assert "unix_sockets" not in policy
    assert "enabled=true" not in policy
    assert "allow_upstream_proxy=false" in policy
    assert "/var/run/docker.sock" not in policy

    with pytest.raises(ValueError, match="broker endpoint"):
        backend.build_exec_argv(CodexExecRequest(workdir=staging.workdir, prompt="diagnose"))


class _KillableProcess:
    pid = 32123

    def __init__(self, *, output: str = "line\n") -> None:
        self.stdout = StringIO(output)
        self.stderr = StringIO("")
        self.killed = False

    def poll(self):
        return -signal.SIGKILL if self.killed else None

    def wait(self, timeout: float | None = None):
        if self.killed:
            return -signal.SIGKILL
        raise __import__("subprocess").TimeoutExpired("codex", timeout)


def test_callback_exception_and_cancellation_reap_only_the_child_process_group(sterile_staging_factory) -> None:
    calls: list[tuple[int, signal.Signals]] = []
    process = _KillableProcess()
    staging = sterile_staging_factory()
    socket_path = staging.workdir / ".ctf-os-broker"
    socket_path.mkdir(mode=0o700)

    def killpg(pid: int, sig: signal.Signals) -> None:
        calls.append((pid, sig))
        if sig is signal.SIGKILL:
            process.killed = True

    backend = CodexCliBackend(model_router=_router(), process_factory=lambda *_a, **_k: process, killpg=killpg)
    request = CodexExecRequest(workdir=staging.workdir, prompt="x", broker_socket=socket_path)
    with pytest.raises(RuntimeError, match="evidence failed"):
        backend.run(request, term_grace_sec=0, on_output=lambda _record: (_ for _ in ()).throw(RuntimeError("evidence failed")))
    assert calls == [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]

    calls.clear()
    process = _KillableProcess(output="")
    cancelled = Event()
    cancelled.set()
    backend = CodexCliBackend(model_router=_router(), process_factory=lambda *_a, **_k: process, killpg=killpg)
    result = backend.run(request, term_grace_sec=0, cancel_event=cancelled)
    assert result.timed_out and calls == [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]


def test_evidence_sink_exception_also_reaps_the_private_process_group(sterile_staging_factory) -> None:
    calls: list[tuple[int, signal.Signals]] = []
    process = _KillableProcess()
    staging = sterile_staging_factory()
    socket_path = staging.workdir / ".ctf-os-broker"
    socket_path.mkdir(mode=0o700)

    def killpg(pid: int, sig: signal.Signals) -> None:
        calls.append((pid, sig))
        if sig is signal.SIGKILL:
            process.killed = True

    backend = CodexCliBackend(model_router=_router(), process_factory=lambda *_a, **_k: process, killpg=killpg)
    with pytest.raises(OSError, match="disk full"):
        backend.run(
            CodexExecRequest(workdir=staging.workdir, prompt="x", broker_socket=socket_path),
            term_grace_sec=0,
            evidence_sink=lambda _record: (_ for _ in ()).throw(OSError("disk full")),
        )
    assert calls == [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]


def test_attempt_broker_authenticates_and_executes_only_docker_exec_argv(sterile_staging_factory) -> None:
    workdir = sterile_staging_factory().workdir
    runner = RecordingCommandRunner(stdout="ok\n")
    docker = DockerCli(runner=runner)
    broker = AttemptCommandBroker(attempt_id="attempt-a", container_name="ctf-os-a", workdir=workdir, docker=docker, token="x" * 32)
    broker.start()
    try:
        helper = create_ctf_exec_helper(workdir / "ctf-exec", broker=broker)
        contents = helper.read_text(encoding="utf-8")
        assert helper.parent == workdir and str(broker.socket_path) in contents
        assert "docker" not in contents and "import socket" not in contents
        assert stat.S_IMODE(helper.stat().st_mode) == 0o700
        assert broker.socket_path == workdir / ".ctf-os-broker"
        assert broker.socket_path.is_dir()

        result = send_broker_request(broker.socket_path, attempt_id="attempt-a", token="x" * 32, argv=["file", "/workspace/chall"])
        assert result.stdout == "ok\n"
        assert runner.calls == [["docker", "exec", "--user", "ctf", "-w", "/work", "ctf-os-a", "file", "/workspace/chall"]]
        with pytest.raises(BrokerError, match="authentication"):
            send_broker_request(broker.socket_path, attempt_id="attempt-a", token="y" * 32, argv=["id"])
        with pytest.raises(BrokerError, match="different attempt"):
            send_broker_request(broker.socket_path, attempt_id="attempt-b", token="x" * 32, argv=["id"])
        with pytest.raises(BrokerError, match="exceeds"):
            send_broker_request(broker.socket_path, attempt_id="attempt-a", token="x" * 32, argv=["x" * (MAX_BROKER_MESSAGE_BYTES + 1)])
    finally:
        socket_path = broker.socket_path
        broker.stop()
    assert not socket_path.exists()


def _resolver(host: str, port: int, family: int, socktype: int):
    assert family == socket.AF_UNSPEC and socktype == socket.SOCK_STREAM
    if ":" in host:
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (host, port, 0, 0))]
    if host.count(".") == 3 and all(part.isdigit() for part in host.split(".")):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", port, 0, 0)),
    ]


@pytest.mark.parametrize(
    ("remote", "protocol", "port"),
    [("nc pwn.ctf.test 31337", "nc", 31337)],
)
def test_remote_parser_resolution_and_egress_run_policy(remote: str, protocol: str, port: int, tmp_path: Path, sterile_staging_factory) -> None:
    declared = parse_remote_endpoints(remote)
    assert declared[0].protocol == protocol and declared[0].port == port
    allowed = resolve_remote_endpoints(declared, resolver=_resolver)
    argv = build_docker_run_argv(_spec(tmp_path, staging=sterile_staging_factory(), endpoints=allowed))
    assert ["--network", "bridge"] == argv[argv.index("--network") : argv.index("--network") + 2]
    assert "--add-host" in argv
    if protocol == "nc":
        assert f"{declared[0].host}:8.8.8.8" in argv
    policy = next(item for item in argv if item.startswith("CTF_OS_ALLOWED_ENDPOINTS_JSON="))
    assert '"port":' + str(port) in policy and '"protocol":"tcp"' in policy


@pytest.mark.parametrize("remote", ["http://web.ctf.test", "https://web.ctf.test:4443/a"])
def test_http_hostname_remotes_fail_closed(remote: str) -> None:
    with pytest.raises(RemotePolicyError, match="HTTP\\(S\\)"):
        parse_remote_endpoints(remote)


@pytest.mark.parametrize("remote", ["ftp://x.test", "http://", "nc x.test -1", "nc x.test 1 extra", "http://user@x.test", "x.test:1234", "http://x.test bad"])
def test_remote_parser_rejects_malformed_or_ambiguous_declarations(remote: str) -> None:
    with pytest.raises(RemotePolicyError):
        parse_remote_endpoints(remote)


def test_no_remote_uses_network_none_and_cleanup_all_retains_team_member(tmp_path: Path, sterile_staging_factory) -> None:
    argv = build_docker_run_argv(_spec(tmp_path, staging=sterile_staging_factory()))
    assert ["--network", "none"] == argv[argv.index("--network") : argv.index("--network") + 2]
    filters = build_cleanup_filters(SandboxScope("team", "member", "c", "x"), all_containers=True)
    assert "label=ctf-os.team_id=team" in filters and "label=ctf-os.member=member" in filters


def _write_config(tmp_path: Path, contest: str = "Demo") -> AppConfig:
    mapping = default_config_mapping(contest)
    mapping["model_routing"]["enabled"] = False
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(mapping), encoding="utf-8")
    return AppConfig.from_file(path)


def test_manifest_must_be_exact_configured_path_and_identity(tmp_path: Path) -> None:
    config = _write_config(tmp_path)
    other = tmp_path / "incoming" / "Other" / "contest.md"
    other.parent.mkdir(parents=True)
    other.write_text("# 대회명: Demo\n\n### web/a\n- 점수: 1\n", encoding="utf-8")
    from ctf_os.intake import IntakeService

    assert IntakeService(config).discover_manifests() == ()
    manifest = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("# 대회명: Different\n\n### web/a\n- 점수: 1\n", encoding="utf-8")
    with pytest.raises(IntakeError, match="both exactly match"):
        IntakeService(config).discover_manifests()


def test_zip_limits_and_failed_extraction_preserve_existing_workspace(tmp_path: Path) -> None:
    destination = tmp_path / "workspace"
    destination.mkdir()
    (destination / "keep.txt").write_text("old", encoding="utf-8")
    too_many = tmp_path / "many.zip"
    with ZipFile(too_many, "w") as bundle:
        bundle.writestr("one", b"1")
        bundle.writestr("two", b"2")
    with pytest.raises(IntakeError, match="file-count"):
        extract_zip_safely(too_many, destination, limits=ZipExtractionLimits(max_files=1, max_file_bytes=10, max_total_bytes=10, max_compression_ratio=10))

    ratio = tmp_path / "ratio.zip"
    with ZipFile(ratio, "w", ZIP_DEFLATED) as bundle:
        bundle.writestr("compressible", b"A" * 10_000)
    with pytest.raises(IntakeError, match="compression-ratio"):
        extract_zip_safely(ratio, destination, limits=ZipExtractionLimits(max_files=5, max_file_bytes=20_000, max_total_bytes=20_000, max_compression_ratio=2))

    partial = tmp_path / "partial.zip"
    with ZipFile(partial, "w") as bundle:
        bundle.writestr("first", b"1234")
        bundle.writestr("second", b"5678")
    with pytest.raises(IntakeError, match="total expanded"):
        extract_zip_safely(partial, destination, limits=ZipExtractionLimits(max_files=5, max_file_bytes=10, max_total_bytes=6, max_compression_ratio=20))
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "old"
    assert not (destination / "first").exists()


def test_docker_inputs_reject_options_and_image_injection_and_exec_is_ctf_user(tmp_path: Path, sterile_staging_factory) -> None:
    with pytest.raises(ValueError, match="image"):
        replace(_spec(tmp_path, staging=sterile_staging_factory()), image="--privileged")
    with pytest.raises(ValueError, match="start with"):
        SandboxScope("-team", "member", "c", "x")
    with pytest.raises(ValueError, match="start with"):
        build_docker_exec_argv("ctf-os-a", ["--help"])
    assert build_docker_exec_argv("ctf-os-a", ["id"])[:5] == ["docker", "exec", "--user", "ctf", "-w"]


def test_sandbox_image_uses_firewall_entrypoint_and_privilege_drop() -> None:
    dockerfile = (Path(__file__).parents[1] / "sandbox" / "Dockerfile.sandbox").read_text(encoding="utf-8")
    entrypoint = (Path(__file__).parents[1] / "sandbox" / "entrypoint.sh").read_text(encoding="utf-8")
    assert "ruby" in dockerfile and "gem install --no-document zsteg" in dockerfile
    assert "iptables util-linux" in dockerfile and "ENTRYPOINT" in dockerfile
    assert '"$tool" -P OUTPUT DROP' in entrypoint and "apply_firewall ip6tables" in entrypoint
    assert "ESTABLISHED,RELATED" in entrypoint and "setpriv --reuid=ctf" in entrypoint


def _firewall_harness(tmp_path: Path) -> tuple[Path, Path]:
    tools = tmp_path / "tools"
    tools.mkdir()
    log = tmp_path / "firewall.log"
    for name in ("iptables", "ip6tables"):
        tool = tools / name
        tool.write_text(
            "#!/bin/sh\n"
            'printf "%s %s\\n" "$(basename "$0")" "$*" >> "$CTF_OS_FIREWALL_LOG"\n',
            encoding="utf-8",
        )
        tool.chmod(0o700)
    jq = tools / "jq"
    jq.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for item in json.load(sys.stdin):\n"
        "    print(f\"{item.get('ip', '')}\\t{item.get('port', '')}\\t{item.get('protocol', '')}\")\n",
        encoding="utf-8",
    )
    jq.chmod(0o700)
    setpriv = tools / "setpriv"
    setpriv.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n'
        'if [ "$#" -gt 0 ]; then shift; fi\n'
        'exec "$@"\n',
        encoding="utf-8",
    )
    setpriv.chmod(0o700)
    return tools, log


def _run_entrypoint(tmp_path: Path, policy: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
    tools, log = _firewall_harness(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{tools}:{os.environ.get('PATH', '')}",
        "CTF_OS_FIREWALL_LOG": str(log),
        "CTF_OS_ALLOWED_ENDPOINTS_JSON": json.dumps(policy),
    }
    return subprocess.run(
        ["bash", str(Path(__file__).parents[1] / "sandbox" / "entrypoint.sh"), "true"],
        check=False,
        text=True,
        capture_output=True,
        env=env,
        timeout=5,
    )


@pytest.mark.parametrize(
    ("policy", "ipv4", "ipv6"),
    [
        ([], (), ()),
        ([{"ip": "8.8.8.8", "port": 31337, "protocol": "tcp"}], ("8.8.8.8",), ()),
        ([{"ip": "2001:4860:4860::8888", "port": 443, "protocol": "tcp"}], (), ("2001:4860:4860::8888",)),
        (
            [
                {"ip": "8.8.4.4", "port": 80, "protocol": "tcp"},
                {"ip": "2001:4860:4860::8844", "port": 443, "protocol": "tcp"},
            ],
            ("8.8.4.4",),
            ("2001:4860:4860::8844",),
        ),
    ],
)
def test_firewall_entrypoint_splits_empty_ipv4_ipv6_and_mixed_rules(tmp_path: Path, policy, ipv4, ipv6) -> None:
    result = _run_entrypoint(tmp_path, policy)
    assert result.returncode == 0, result.stderr
    lines = (tmp_path / "firewall.log").read_text(encoding="utf-8").splitlines()
    for address in ipv4:
        assert any(line.startswith("iptables -A OUTPUT -p tcp") and f"-d {address} " in line for line in lines)
        assert not any(line.startswith("ip6tables -A OUTPUT -p tcp") and f"-d {address} " in line for line in lines)
    for address in ipv6:
        assert any(line.startswith("ip6tables -A OUTPUT -p tcp") and f"-d {address} " in line for line in lines)
        assert not any(line.startswith("iptables -A OUTPUT -p tcp") and f"-d {address} " in line for line in lines)
    if not policy:
        assert not any(" -d " in line for line in lines)


@pytest.mark.parametrize(
    "policy",
    [
        [{"ip": "8.8.8.8", "port": 0, "protocol": "tcp"}],
        [{"ip": "8.8.8.8", "port": 80, "protocol": "udp"}],
    ],
)
def test_firewall_entrypoint_rejects_invalid_policy(tmp_path: Path, policy) -> None:
    result = _run_entrypoint(tmp_path, policy)
    assert result.returncode == 64


def test_docker_cli_hard_bounds_runner_output() -> None:
    payload = "A" * 2048

    def runner(argv: list[str]) -> CommandResult:
        return CommandResult(tuple(argv), stdout=payload, stderr=payload)

    result = DockerCli(runner=runner, max_output_bytes=1024).invoke(["docker", "ps"])
    assert result.truncated
    assert len(result.stdout.encode("utf-8")) <= 1024
    assert "[ctf-os docker output truncated]" in result.stderr
    assert "A" * 512 not in result.stderr


def test_broker_timeout_and_stop_cancel_remove_container_and_join(tmp_path: Path, sterile_staging_factory) -> None:
    class TimeoutDocker(DockerCli):
        def __init__(self) -> None:
            super().__init__(runner=RecordingCommandRunner())
            self.removed: list[str] = []

        def exec(self, argv, *, timeout_sec=None, cancel_event=None):
            return CommandResult(tuple(argv), returncode=124, timed_out=True)

        def remove(self, container_name: str) -> CommandResult:
            self.removed.append(container_name)
            return CommandResult(("docker", "rm", "-f", container_name))

    docker = TimeoutDocker()
    broker = AttemptCommandBroker(
        attempt_id="attempt-timeout", container_name="ctf-os-timeout",
        workdir=sterile_staging_factory().workdir, docker=docker, token="x" * 32,
    ).start()
    try:
        result = send_broker_request(broker.socket_path, attempt_id="attempt-timeout", token="x" * 32, argv=["id"])
        assert result.timed_out
        assert docker.removed == ["ctf-os-timeout"]
    finally:
        broker.stop()
    assert not broker.running


def test_broker_stop_cancels_active_command_removes_container_and_joins(tmp_path: Path, sterile_staging_factory) -> None:
    class BlockingDocker(DockerCli):
        def __init__(self) -> None:
            super().__init__(runner=RecordingCommandRunner())
            self.started = Event()
            self.removed: list[str] = []

        def exec(self, argv, *, timeout_sec=None, cancel_event=None):
            self.started.set()
            assert cancel_event is not None
            cancel_event.wait(2)
            return CommandResult(tuple(argv), returncode=124, timed_out=True)

        def remove(self, container_name: str) -> CommandResult:
            self.removed.append(container_name)
            return CommandResult(("docker", "rm", "-f", container_name))

    docker = BlockingDocker()
    broker = AttemptCommandBroker(
        attempt_id="attempt-cancel", container_name="ctf-os-cancel",
        workdir=sterile_staging_factory().workdir, docker=docker, token="x" * 32,
    ).start()
    errors: list[BaseException] = []

    def client() -> None:
        try:
            send_broker_request(broker.socket_path, attempt_id="attempt-cancel", token="x" * 32, argv=["id"], timeout_sec=3)
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=client)
    thread.start()
    assert docker.started.wait(2)
    broker.stop()
    thread.join(2)
    assert not thread.is_alive()
    assert not broker.running
    assert docker.removed == ["ctf-os-cancel"]
