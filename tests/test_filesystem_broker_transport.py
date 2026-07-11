from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
from threading import Event, Thread
import time

from ctf_os.sandbox.broker import (
    AttemptCommandBroker,
    MAX_BROKER_MESSAGE_BYTES,
    create_ctf_exec_helper,
    send_broker_request,
)
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner


def test_filesystem_spool_supports_concurrent_authenticated_argv_requests(sterile_staging_factory) -> None:
    staging = sterile_staging_factory()

    class EchoDocker(DockerCli):
        def exec(self, argv, *, timeout_sec=None, cancel_event=None):
            return CommandResult(tuple(argv), stdout=argv[-1] + "\n")

    broker = AttemptCommandBroker(
        attempt_id="attempt-concurrent", container_name="ctf-os-concurrent",
        workdir=staging.workdir, docker=EchoDocker(runner=RecordingCommandRunner()), token="x" * 32,
    ).start()
    results: dict[str, str] = {}
    errors: list[BaseException] = []
    try:
        helper = create_ctf_exec_helper(staging.workdir / "ctf-exec", broker=broker)
        assert "import socket" not in helper.read_text(encoding="utf-8")

        def invoke(value: str) -> None:
            try:
                result = send_broker_request(
                    broker.socket_path, attempt_id="attempt-concurrent",
                    token="x" * 32, argv=["printf", value], timeout_sec=2,
                )
                results[value] = result.stdout
            except BaseException as exc:
                errors.append(exc)

        threads = [Thread(target=invoke, args=(str(index),)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)
        assert not errors
        assert results == {str(index): f"{index}\n" for index in range(4)}
    finally:
        endpoint = broker.socket_path
        broker.stop()
    assert not endpoint.exists()


def test_spool_snapshot_tolerates_rename_races_during_many_concurrent_rounds(sterile_staging_factory) -> None:
    """A vanished directory entry is a normal spool race, not broker death."""
    staging = sterile_staging_factory()

    class EchoDocker(DockerCli):
        def exec(self, argv, *, timeout_sec=None, cancel_event=None):
            return CommandResult(tuple(argv), stdout=argv[-1] + "\n")

    broker = AttemptCommandBroker(
        attempt_id="attempt-race", container_name="ctf-os-race", workdir=staging.workdir,
        docker=EchoDocker(runner=RecordingCommandRunner()), token="x" * 32,
    ).start()
    stop_racer = Event()
    racer: Thread | None = None
    try:
        endpoint = broker.socket_path

        def rename_noise() -> None:
            index = 0
            endpoint_fd = os.open(endpoint, os.O_RDONLY | os.O_DIRECTORY)
            try:
                while not stop_racer.is_set():
                    source = f".race-{index % 2}"
                    destination = f".race-moved-{index % 2}"
                    try:
                        descriptor = os.open(
                            source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                            dir_fd=endpoint_fd,
                        )
                    except FileExistsError:
                        try:
                            os.unlink(source, dir_fd=endpoint_fd)
                        except FileNotFoundError:
                            pass
                    else:
                        os.close(descriptor)
                        try:
                            os.rename(source, destination, src_dir_fd=endpoint_fd, dst_dir_fd=endpoint_fd)
                            os.unlink(destination, dir_fd=endpoint_fd)
                        except FileNotFoundError:
                            pass
                    index += 1
            finally:
                os.close(endpoint_fd)

        racer = Thread(target=rename_noise, daemon=True)
        racer.start()
        for round_number in range(50):
            results: dict[str, str] = {}
            errors: list[BaseException] = []

            def invoke(value: str) -> None:
                try:
                    reply = send_broker_request(
                        broker.socket_path, attempt_id="attempt-race", token="x" * 32,
                        argv=["printf", value], timeout_sec=5,
                    )
                    results[value] = reply.stdout
                except BaseException as exc:
                    errors.append(exc)

            values = [f"{round_number}-{worker}" for worker in range(8)]
            workers = [Thread(target=invoke, args=(value,)) for value in values]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
            assert not errors
            assert results == {value: value + "\n" for value in values}
            assert broker.running
    finally:
        stop_racer.set()
        if racer is not None:
            racer.join(2)
        broker.stop()


def test_spool_rejects_symlink_hardlink_and_partial_request_without_docker(sterile_staging_factory, tmp_path: Path) -> None:
    staging = sterile_staging_factory()
    runner = RecordingCommandRunner()
    broker = AttemptCommandBroker(
        attempt_id="attempt-hostile", container_name="ctf-os-hostile", workdir=staging.workdir,
        docker=DockerCli(runner=runner), token="x" * 32,
    ).start()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    try:
        endpoint = broker.socket_path
        assert broker.session_id is not None
        prefix = "request-" + broker.session_id + "-"
        (endpoint / (prefix + "a" * 32)).symlink_to(outside)

        source = endpoint / "hardlink-source"
        source.write_bytes(struct.pack("!I", 2) + b"{}")
        os.chmod(source, 0o600)
        os.link(source, endpoint / (prefix + "b" * 32))

        partial = endpoint / (prefix + "c" * 32)
        partial.write_bytes(struct.pack("!I", MAX_BROKER_MESSAGE_BYTES))
        os.chmod(partial, 0o600)

        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and any(
            (endpoint / (prefix + value * 32)).exists()
            for value in ("a", "b", "c")
        ):
            time.sleep(0.01)
        assert not runner.calls
        assert outside.read_bytes() == b"outside"
        assert source.stat().st_nlink == 1
        assert broker.running
    finally:
        broker.stop()


def test_spool_endpoint_and_helper_are_exact_owned_nonlinked_entries(sterile_staging_factory) -> None:
    staging = sterile_staging_factory()
    broker = AttemptCommandBroker(
        attempt_id="attempt-modes", container_name="ctf-os-modes", workdir=staging.workdir,
        docker=DockerCli(runner=RecordingCommandRunner()), token="x" * 32,
    ).start()
    try:
        helper = create_ctf_exec_helper(staging.workdir / "ctf-exec", broker=broker)
        endpoint_info = broker.socket_path.lstat()
        helper_info = helper.lstat()
        assert broker.socket_path.parent == staging.workdir
        assert stat.S_ISDIR(endpoint_info.st_mode)
        assert endpoint_info.st_uid == os.getuid() and stat.S_IMODE(endpoint_info.st_mode) == 0o700
        assert stat.S_ISREG(helper_info.st_mode) and helper_info.st_nlink == 1
        assert helper_info.st_uid == os.getuid() and stat.S_IMODE(helper_info.st_mode) == 0o700
    finally:
        broker.stop()
