from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import ctf_os.sandbox.files as sandbox_files
from ctf_os.analysis_leases import AnalysisLeaseManager
from ctf_os.models import ChallengeIdentity
from ctf_os.sandbox.client import (
    LocalChallengeSandboxClient,
    UnixChallengeSandboxClient,
    result_from_dict,
)
from ctf_os.sandbox.daemon import CapabilityAuthority, SandboxService
from ctf_os.sandbox.docker import DockerLimits, DockerSandboxBackend
from ctf_os.sandbox.files import SafeFileError
from ctf_os.sandbox.types import (
    AnalysisLeaseRef,
    AnalysisRuntimeCleanupPending,
    BackgroundJobUnsupported,
    ChallengeScope,
    CommandSpec,
    SandboxError,
    SandboxResult,
    ScopeError,
)
from ctf_os.store import StateStore


IMAGE_DIGEST = "sha256:" + "a" * 64


class _AnalysisRunner:
    def __init__(self, challenge: Path) -> None:
        self.challenge = challenge
        self.calls: list[tuple[str, ...]] = []
        self.command_barrier: threading.Barrier | None = None

    @staticmethod
    def _work_mount(command: tuple[str, ...]) -> Path:
        mount = next(
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "--mount" and "dst=/work" in command[index + 1]
        )
        source = next(
            field.removeprefix("src=")
            for field in mount.split(",")
            if field.startswith("src=")
        )
        return Path(source)

    def __call__(self, command, **_kwargs):
        values = tuple(command)
        self.calls.append(values)
        if values[1:4] == ("container", "ls", "--all"):
            return subprocess.CompletedProcess(values, 0, "", "")
        if values[1] != "run":
            raise AssertionError(f"unexpected Docker command: {values}")
        work = self._work_mount(values)
        if "ctfwrap" not in values:
            for source in self.challenge.rglob("*"):
                relative = source.relative_to(self.challenge)
                destination = work / relative
                if source.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
            return subprocess.CompletedProcess(values, 0, "", "")

        barrier = self.command_barrier
        if barrier is not None:
            barrier.wait(timeout=5)
        run_id = "run-00000001"
        run_root = work / ".ctf" / "runs" / run_id
        run_root.mkdir(parents=True)
        stdout = b"isolated\n"
        stderr = b""
        (run_root / "stdout.log").write_bytes(stdout)
        (run_root / "stderr.log").write_bytes(stderr)
        started_at = datetime.now(UTC)
        finished_at = started_at + timedelta(milliseconds=1)
        timeout_seconds = int(values[values.index("--timeout") + 1])
        value = {
            "duration_ms": 1,
            "exit_code": 0,
            "kind": "run_result",
            "run_id": run_id,
            "schema_version": 1,
            "status": "completed",
            "stderr_bytes": 0,
            "stderr_path": f"/work/.ctf/runs/{run_id}/stderr.log",
            "stderr_summary": "",
            "stdout_bytes": len(stdout),
            "stdout_path": f"/work/.ctf/runs/{run_id}/stdout.log",
            "stdout_summary": stdout.decode("ascii"),
            "timed_out": False,
            "timeout_seconds": timeout_seconds,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }
        (run_root / "result.json").write_text(
            json.dumps(value),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(values, 0, json.dumps(value), "")


class IsolatedAnalysisSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.canonical = self.root / "canonical"
        self.analysis_root = self.root / "runtime" / "analysis"
        self.challenge.mkdir()
        self.canonical.mkdir()
        self.analysis_root.mkdir(parents=True, mode=0o700)
        self.analysis_root.chmod(0o700)
        (self.challenge / "challenge.txt").write_bytes(b"challenge\n")
        source = self.canonical / "declared" / "input.bin"
        source.parent.mkdir()
        source.write_bytes(b"canonical bytes\n")
        self.scope = ChallengeScope.create(
            contest_id="analysis-tests",
            category="pwn",
            challenge_id="isolated",
            challenge_dir=self.challenge,
            work_dir=self.canonical,
        )
        self.runner = _AnalysisRunner(self.challenge)
        self.backend = DockerSandboxBackend(
            self.scope,
            analysis_root=self.analysis_root,
            image_digest=IMAGE_DIGEST,
            limits=DockerLimits(work_tree_max_bytes=1024 * 1024),
            runner=self.runner,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lease(self, suffix: str) -> tuple[AnalysisLeaseRef, Path]:
        analysis_id = f"analysis-{suffix * 32}"
        root = self.analysis_root / analysis_id
        work = root / "work"
        work.mkdir(parents=True, mode=0o700)
        root.chmod(0o700)
        work.chmod(0o700)
        root_metadata = root.stat(follow_symlinks=False)
        work_metadata = work.stat(follow_symlinks=False)
        (root / "owner.json").write_text(
            json.dumps(
                {
                    "analysis_id": analysis_id,
                    "base_revision": 0,
                    "created_at": "2026-07-31T00:00:00Z",
                    "owner_boot_id": "00000000-0000-0000-0000-000000000000",
                    "owner_pid": os.getpid(),
                    "owner_start_ticks": 1,
                    "root_device": root_metadata.st_dev,
                    "root_inode": root_metadata.st_ino,
                    "schema_version": 1,
                    "scope_fingerprint": self.scope.fingerprint,
                    "storage_reservation_bytes": 1024 * 1024,
                    "work_device": work_metadata.st_dev,
                    "work_inode": work_metadata.st_ino,
                    "work_tree_limit_bytes": 1024 * 1024,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        (root / "owner.json").chmod(0o400)
        return AnalysisLeaseRef(analysis_id, self.scope.fingerprint), work

    def test_declared_input_only_and_canonical_workspace_is_never_mounted(
        self,
    ) -> None:
        lease, work = self.lease("a")
        before = (self.canonical / "declared" / "input.bin").read_bytes()

        spec = CommandSpec(("sha256sum", "declared/input.bin"))
        result = self.backend.run_isolated_analysis(
            lease,
            spec,
            input_locators=("declared/input.bin",),
        )
        self.assertEqual(result.timeout_seconds, spec.timeout_seconds)
        self.assertIsNotNone(result.started_at)
        self.assertIsNotNone(result.finished_at)

        self.assertEqual(
            (work / "declared" / "input.bin").read_bytes(),
            before,
        )
        self.assertEqual(
            (self.canonical / "declared" / "input.bin").read_bytes(),
            before,
        )
        run_calls = [call for call in self.runner.calls if call[1] == "run"]
        self.assertEqual(len(run_calls), 2)
        for call in run_calls:
            mount_values = [
                call[index + 1]
                for index, value in enumerate(call[:-1])
                if value == "--mount"
            ]
            self.assertFalse(
                any(f"src={self.canonical}" in value for value in mount_values)
            )
            self.assertTrue(any("dst=/challenge" in value for value in mount_values))
            self.assertTrue(any("dst=/work" in value for value in mount_values))
        self.assertEqual(
            result.stdout_path,
            "/work/.ctf/runs/run-00000001/stdout.log",
        )
        self.assertEqual(result.proof_outputs, ())
        self.assertEqual(
            self.backend.isolated_analysis_runtime_id(lease),
            f"ctfos-analysis-{self.scope.fingerprint[:12]}-"
            f"{'a' * 20}-run",
        )

    def test_two_private_readers_overlap_without_sharing_work(self) -> None:
        first, first_work = self.lease("b")
        second, second_work = self.lease("c")
        self.runner.command_barrier = threading.Barrier(2)
        failures: list[BaseException] = []

        def execute(lease: AnalysisLeaseRef) -> None:
            try:
                self.backend.run_isolated_analysis(
                    lease,
                    CommandSpec(("true",)),
                )
            except BaseException as error:
                failures.append(error)

        threads = [
            threading.Thread(target=execute, args=(first,)),
            threading.Thread(target=execute, args=(second,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertTrue((first_work / ".ctf").is_dir())
        self.assertTrue((second_work / ".ctf").is_dir())

    def test_owner_bound_work_replacement_is_rejected(self) -> None:
        lease, work = self.lease("d")
        displaced = work.with_name("displaced")
        work.rename(displaced)
        work.mkdir(mode=0o700)
        with self.assertRaisesRegex(ScopeError, "work directory is unsafe"):
            self.backend.run_isolated_analysis(lease, CommandSpec(("true",)))
        self.assertEqual(self.runner.calls, [])

    def test_declared_input_rejects_symlink_fifo_and_external_hardlink(
        self,
    ) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "payload.bin").write_bytes(b"outside")
        final_link = self.canonical / "final-link.bin"
        final_link.symlink_to(outside / "payload.bin")
        parent_link = self.canonical / "parent-link"
        parent_link.symlink_to(outside, target_is_directory=True)
        fifo = self.canonical / "input.pipe"
        os.mkfifo(fifo)
        hardlink = self.canonical / "hardlink.bin"
        hardlink.write_bytes(b"hardlink")
        os.link(hardlink, outside / "external-hardlink.bin")
        cases = (
            ("4", "final-link.bin"),
            ("5", "parent-link/payload.bin"),
            ("6", "input.pipe"),
            ("7", "hardlink.bin"),
        )
        for suffix, locator in cases:
            with self.subTest(locator=locator):
                lease, _work = self.lease(suffix)
                with self.assertRaisesRegex(
                    ScopeError,
                    "could not be copied safely",
                ):
                    self.backend.run_isolated_analysis(
                        lease,
                        CommandSpec(("true",)),
                        input_locators=(locator,),
                    )
        self.assertEqual((outside / "payload.bin").read_bytes(), b"outside")
        self.assertEqual(
            (outside / "external-hardlink.bin").read_bytes(),
            b"hardlink",
        )
        self.assertFalse(
            any("ctfwrap" in call for call in self.runner.calls)
        )

    def test_declared_input_rejects_replace_and_growth_during_copy(self) -> None:
        real_copy = sandbox_files.copy_bounded_regular
        for suffix, mutation in (("8", "replace"), ("9", "grow")):
            with self.subTest(mutation=mutation):
                source = self.canonical / "declared" / "race.bin"
                source.write_bytes(b"initial")
                lease, _work = self.lease(suffix)

                def racing_copy(*args, **kwargs):
                    admission = kwargs["source_size_admission"]

                    def mutate(size: int) -> None:
                        admission(size)
                        if mutation == "replace":
                            replacement = source.with_name("replacement.bin")
                            replacement.write_bytes(b"replace")
                            os.replace(replacement, source)
                        else:
                            source.write_bytes(b"initial-growth")

                    kwargs["source_size_admission"] = mutate
                    return real_copy(*args, **kwargs)

                with (
                    mock.patch(
                        "ctf_os.sandbox.docker.copy_bounded_regular",
                        side_effect=racing_copy,
                    ),
                    self.assertRaisesRegex(
                        ScopeError,
                        "could not be copied safely",
                    ),
                ):
                    self.backend.run_isolated_analysis(
                        lease,
                        CommandSpec(("true",)),
                        input_locators=("declared/race.bin",),
                    )

    def test_input_sequence_count_and_locator_bounds_fail_before_docker(
        self,
    ) -> None:
        cases = (
            tuple(f"input-{index}" for index in range(257)),
            ("x" * 4097,),
            "declared/input.bin",
        )
        for index, values in enumerate(cases):
            with self.subTest(case=index):
                lease, _work = self.lease(f"{index + 10:032x}"[-1])
                before = len(self.runner.calls)
                with self.assertRaises((ValueError, ScopeError)):
                    self.backend.run_isolated_analysis(
                        lease,
                        CommandSpec(("true",)),
                        input_locators=values,  # type: ignore[arg-type]
                    )
                self.assertEqual(len(self.runner.calls), before)

    def test_analysis_never_uses_persistent_ensure_or_detach(self) -> None:
        lease, _work = self.lease("a")
        with mock.patch.object(
            self.backend,
            "_ensure_container",
            side_effect=AssertionError("persistent ensure called"),
        ) as ensure:
            self.backend.run_isolated_analysis(
                lease,
                CommandSpec(("true",)),
            )
        ensure.assert_not_called()
        run_calls = [call for call in self.runner.calls if call[1] == "run"]
        self.assertEqual(len(run_calls), 2)
        self.assertTrue(all("--detach" not in call for call in run_calls))

    def test_result_output_credential_audit_is_mandatory(self) -> None:
        lease, work = self.lease("b")
        with (
            mock.patch.object(
                self.backend,
                "_audit_run_credentials",
                side_effect=SandboxError("synthetic credential audit failure"),
            ) as audit,
            self.assertRaisesRegex(SandboxError, "credential audit failure"),
        ):
            self.backend.run_isolated_analysis(
                lease,
                CommandSpec(("true",)),
            )
        audit.assert_called_once()
        self.assertTrue((work / ".ctf" / "runs").is_dir())

    def test_timeout_and_baseexception_remove_and_attest_exact_runtime(
        self,
    ) -> None:
        for suffix, interruption in (
            ("c", subprocess.TimeoutExpired("docker", 1)),
            ("d", KeyboardInterrupt("synthetic interrupt")),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                lease, work = self.lease(suffix)
                runtime_id = self.backend.isolated_analysis_runtime_id(lease)
                present = False
                removals: list[str] = []

                def runner(command, **_kwargs):
                    nonlocal present
                    values = tuple(command)
                    if values[1:4] == ("container", "ls", "--all"):
                        target = values[-1].removeprefix(
                            "name=^/"
                        ).removesuffix("$")
                        return subprocess.CompletedProcess(
                            values,
                            0,
                            (
                                "0123456789ab\n"
                                if present and target == runtime_id
                                else ""
                            ),
                            "",
                        )
                    if values[1:3] == ("container", "inspect"):
                        details = {
                            "Config": {
                                "Image": self.backend.image_reference,
                                "Labels": {
                                    "ctfos.analysis": lease.analysis_id,
                                    "ctfos.analysis_phase": "run",
                                    "ctfos.challenge": self.scope.qualified_id,
                                    "ctfos.image": self.backend.image,
                                    "ctfos.image_digest": IMAGE_DIGEST,
                                    "ctfos.managed": "true",
                                    "ctfos.scope": self.scope.fingerprint,
                                },
                            },
                            "Image": IMAGE_DIGEST,
                            "Mounts": [
                                {
                                    "Destination": "/challenge",
                                    "RW": False,
                                    "Source": str(self.challenge),
                                    "Type": "bind",
                                },
                                {
                                    "Destination": "/work",
                                    "RW": True,
                                    "Source": str(work),
                                    "Type": "bind",
                                },
                            ],
                        }
                        return subprocess.CompletedProcess(
                            values,
                            0,
                            json.dumps([details]),
                            "",
                        )
                    if values[1:4] == ("container", "rm", "--force"):
                        removals.append(values[-1])
                        present = False
                        return subprocess.CompletedProcess(values, 0, "", "")
                    if values[1] == "run" and "ctfwrap" not in values:
                        return subprocess.CompletedProcess(values, 0, "", "")
                    if values[1] == "run" and "ctfwrap" in values:
                        present = True
                        raise interruption
                    raise AssertionError(values)

                backend = DockerSandboxBackend(
                    self.scope,
                    analysis_root=self.analysis_root,
                    image_digest=IMAGE_DIGEST,
                    limits=DockerLimits(work_tree_max_bytes=1024 * 1024),
                    runner=runner,
                )
                if isinstance(interruption, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        backend.run_isolated_analysis(
                            lease,
                            CommandSpec(("true",)),
                        )
                    self.assertIs(raised.exception, interruption)
                else:
                    with self.assertRaisesRegex(
                        SandboxError,
                        "control operation timed out",
                    ):
                        backend.run_isolated_analysis(
                            lease,
                            CommandSpec(("true",)),
                        )
                self.assertEqual(removals, [runtime_id])
                self.assertFalse(present)

    def test_operation_and_cleanup_preserve_first_control_exception(
        self,
    ) -> None:
        cases = (
            (
                "4",
                SandboxError("ordinary operation failure"),
                KeyboardInterrupt("cleanup interrupted"),
                KeyboardInterrupt,
                "cleanup",
            ),
            (
                "5",
                KeyboardInterrupt("operation interrupted"),
                SystemExit(81),
                KeyboardInterrupt,
                "operation",
            ),
            (
                "6",
                SandboxError("ordinary operation failure"),
                SandboxError("ordinary cleanup failure"),
                AnalysisRuntimeCleanupPending,
                "typed",
            ),
        )
        for suffix, operation_error, cleanup_error, expected, identity in cases:
            with self.subTest(identity=identity):
                lease, _work = self.lease(suffix)

                def runner(command, **_kwargs):
                    values = tuple(command)
                    if values[1] == "run" and "ctfwrap" not in values:
                        return subprocess.CompletedProcess(values, 0, "", "")
                    if values[1] == "run" and "ctfwrap" in values:
                        raise operation_error
                    raise AssertionError(values)

                backend = DockerSandboxBackend(
                    self.scope,
                    analysis_root=self.analysis_root,
                    image_digest=IMAGE_DIGEST,
                    limits=DockerLimits(
                        work_tree_max_bytes=1024 * 1024
                    ),
                    runner=runner,
                )
                with (
                    mock.patch.object(
                        backend,
                        "cleanup_isolated_analysis",
                        side_effect=(None, None, cleanup_error),
                    ),
                    self.assertRaises(expected) as raised,
                ):
                    backend.run_isolated_analysis(
                        lease,
                        CommandSpec(("true",)),
                    )
                if identity == "cleanup":
                    self.assertIs(raised.exception, cleanup_error)
                elif identity == "operation":
                    self.assertIs(raised.exception, operation_error)
                else:
                    self.assertIsInstance(
                        raised.exception,
                        AnalysisRuntimeCleanupPending,
                    )
                operation_error.__traceback__ = None
                cleanup_error.__traceback__ = None

    def test_background_and_persistent_web_commands_fail_before_docker(self) -> None:
        lease, _work = self.lease("e")
        with self.assertRaises(BackgroundJobUnsupported):
            self.backend.run_isolated_analysis(
                lease,
                CommandSpec(("ctf-bg", "--", "sleep", "1")),
            )
        self.assertEqual(self.runner.calls, [])

        web_scope = ChallengeScope.create(
            contest_id="analysis-tests",
            category="web",
            challenge_id="isolated-web",
            challenge_dir=self.challenge,
            work_dir=self.canonical,
        )
        web_root = self.root / "web-analysis"
        web_root.mkdir(mode=0o700)
        web_backend = DockerSandboxBackend(
            web_scope,
            analysis_root=web_root,
            image_digest=IMAGE_DIGEST,
            limits=DockerLimits(work_tree_max_bytes=1024 * 1024),
            runner=self.runner,
        )
        web_id = "analysis-" + "f" * 32
        web_lease_root = web_root / web_id
        web_work = web_lease_root / "work"
        web_work.mkdir(parents=True, mode=0o700)
        web_lease_root.chmod(0o700)
        web_work.chmod(0o700)
        root_stat = web_lease_root.stat()
        work_stat = web_work.stat()
        (web_lease_root / "owner.json").write_text(
            json.dumps(
                {
                    "analysis_id": web_id,
                    "base_revision": 0,
                    "created_at": "2026-07-31T00:00:00Z",
                    "owner_boot_id": "00000000-0000-0000-0000-000000000000",
                    "owner_pid": os.getpid(),
                    "owner_start_ticks": 1,
                    "root_device": root_stat.st_dev,
                    "root_inode": root_stat.st_ino,
                    "schema_version": 1,
                    "scope_fingerprint": web_scope.fingerprint,
                    "storage_reservation_bytes": 1024 * 1024,
                    "work_device": work_stat.st_dev,
                    "work_inode": work_stat.st_ino,
                    "work_tree_limit_bytes": 1024 * 1024,
                }
            ),
            encoding="utf-8",
        )
        (web_lease_root / "owner.json").chmod(0o400)
        with self.assertRaisesRegex(SandboxError, "persistent Web identities"):
            web_backend.run_isolated_analysis(
                AnalysisLeaseRef(web_id, web_scope.fingerprint),
                CommandSpec(
                    (
                        "ctf-browser",
                        "https://target.test/",
                        "--session",
                        "user",
                    )
                ),
            )
        self.assertEqual(self.runner.calls, [])

    def test_cleanup_uncertainty_is_typed_and_retains_work(self) -> None:
        lease, work = self.lease("1")

        def unavailable(command, **_kwargs):
            return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")

        backend = DockerSandboxBackend(
            self.scope,
            analysis_root=self.analysis_root,
            image_digest=IMAGE_DIGEST,
            runner=unavailable,
        )
        with self.assertRaises(AnalysisRuntimeCleanupPending):
            backend.cleanup_isolated_analysis(lease)
        self.assertTrue(work.is_dir())

    def test_cleanup_verifies_exact_labels_and_mounts_before_removal(self) -> None:
        lease, work = self.lease("2")
        runtime_id = self.backend.isolated_analysis_runtime_id(lease)
        present = True
        removed: list[str] = []

        def runner(command, **_kwargs):
            nonlocal present
            values = tuple(command)
            if values[1:4] == ("container", "ls", "--all"):
                target = values[-1].removeprefix("name=^/").removesuffix("$")
                return subprocess.CompletedProcess(
                    values,
                    0,
                    "0123456789ab\n" if present and target == runtime_id else "",
                    "",
                )
            if values[1:3] == ("container", "inspect"):
                details = {
                    "Config": {
                        "Image": self.backend.image_reference,
                        "Labels": {
                            "ctfos.analysis": lease.analysis_id,
                            "ctfos.analysis_phase": "run",
                            "ctfos.challenge": self.scope.qualified_id,
                            "ctfos.image": self.backend.image,
                            "ctfos.image_digest": IMAGE_DIGEST,
                            "ctfos.managed": "true",
                            "ctfos.scope": self.scope.fingerprint,
                        },
                    },
                    "Image": IMAGE_DIGEST,
                    "Mounts": [
                        {
                            "Destination": "/challenge",
                            "RW": False,
                            "Source": str(self.challenge),
                            "Type": "bind",
                        },
                        {
                            "Destination": "/work",
                            "RW": True,
                            "Source": str(work),
                            "Type": "bind",
                        },
                    ],
                }
                return subprocess.CompletedProcess(
                    values,
                    0,
                    json.dumps([details]),
                    "",
                )
            if values[1:4] == ("container", "rm", "--force"):
                removed.append(values[-1])
                present = False
                return subprocess.CompletedProcess(values, 0, runtime_id, "")
            raise AssertionError(values)

        backend = DockerSandboxBackend(
            self.scope,
            analysis_root=self.analysis_root,
            image_digest=IMAGE_DIGEST,
            runner=runner,
        )
        backend.cleanup_isolated_analysis(lease)
        self.assertEqual(removed, [runtime_id])

    def test_cleanup_rejects_a_container_mounted_to_canonical_work(self) -> None:
        lease, _work = self.lease("3")
        runtime_id = self.backend.isolated_analysis_runtime_id(lease)
        remove_called = False

        def runner(command, **_kwargs):
            nonlocal remove_called
            values = tuple(command)
            if values[1:4] == ("container", "ls", "--all"):
                target = values[-1].removeprefix("name=^/").removesuffix("$")
                return subprocess.CompletedProcess(
                    values,
                    0,
                    "0123456789ab\n" if target == runtime_id else "",
                    "",
                )
            if values[1:3] == ("container", "inspect"):
                details = {
                    "Config": {
                        "Image": self.backend.image_reference,
                        "Labels": {
                            "ctfos.analysis": lease.analysis_id,
                            "ctfos.analysis_phase": "run",
                            "ctfos.challenge": self.scope.qualified_id,
                            "ctfos.image": self.backend.image,
                            "ctfos.image_digest": IMAGE_DIGEST,
                            "ctfos.managed": "true",
                            "ctfos.scope": self.scope.fingerprint,
                        },
                    },
                    "Image": IMAGE_DIGEST,
                    "Mounts": [
                        {
                            "Destination": "/challenge",
                            "RW": False,
                            "Source": str(self.challenge),
                            "Type": "bind",
                        },
                        {
                            "Destination": "/work",
                            "RW": True,
                            "Source": str(self.canonical),
                            "Type": "bind",
                        },
                    ],
                }
                return subprocess.CompletedProcess(
                    values,
                    0,
                    json.dumps([details]),
                    "",
                )
            if values[1:4] == ("container", "rm", "--force"):
                remove_called = True
                return subprocess.CompletedProcess(values, 0, "", "")
            raise AssertionError(values)

        backend = DockerSandboxBackend(
            self.scope,
            analysis_root=self.analysis_root,
            image_digest=IMAGE_DIGEST,
            runner=runner,
        )
        with self.assertRaises(AnalysisRuntimeCleanupPending):
            backend.cleanup_isolated_analysis(lease)
        self.assertFalse(remove_called)


class IsolatedAnalysisRpcTests(unittest.TestCase):
    def test_wire_schema_contains_no_host_path_and_rejects_extra_path(self) -> None:
        fingerprint = "a" * 64
        lease = AnalysisLeaseRef("analysis-" + "b" * 32, fingerprint)

        class Client:
            scope_fingerprint = fingerprint
            include_control_metadata = False

            def isolated_analysis_runtime_id(self, received):
                self.received = received
                return "ctfos-analysis-aaaaaaaaaaaa-" + "b" * 20 + "-run"

            def run_isolated_analysis(self, received, spec, *, input_locators=()):
                self.received = received
                self.spec = spec
                self.inputs = input_locators
                control = (
                    {
                        "timeout_seconds": 900,
                        "started_at": "2026-07-31T00:00:00+00:00",
                        "finished_at": "2026-07-31T00:00:00.001000+00:00",
                    }
                    if self.include_control_metadata
                    else {}
                )
                return SandboxResult(
                    "run-00000001",
                    "completed",
                    0,
                    False,
                    1,
                    "",
                    "",
                    0,
                    0,
                    "/work/.ctf/runs/run-00000001/stdout.log",
                    "/work/.ctf/runs/run-00000001/stderr.log",
                    **control,
                )

            def cleanup_isolated_analysis(self, received):
                self.received = received

        client = Client()
        authority = CapabilityAuthority(b"x" * 32)
        service = SandboxService(authority)
        service.register(client)  # type: ignore[arg-type]
        token = service.issue(fingerprint)
        base = {
            "schema_version": 1,
            "token": token,
            "operation": "run_isolated_analysis",
            "params": {
                "command": {
                    "argv": ["true"],
                    "deadline_monotonic_seconds": None,
                    "environment": {},
                    "network_target": None,
                    "resource_request": {
                        "cpu": 1,
                        "gpu": 0,
                        "kvm": 0,
                        "memory_mib": 2048,
                        "network": 0,
                    },
                    "summary_bytes": 32768,
                    "timeout_seconds": 900,
                },
                "input_locators": ["declared/input.bin"],
                "lease": lease.as_dict(),
            },
        }
        wire = service.dispatch(base)
        self.assertEqual(client.received, lease)
        self.assertEqual(client.inputs, ("declared/input.bin",))
        self.assertNotIn("timeout_seconds", wire)
        self.assertNotIn("started_at", wire)
        self.assertNotIn("finished_at", wire)
        legacy_decoded = result_from_dict(
            json.loads(json.dumps(wire))
        )
        self.assertIsNone(legacy_decoded.timeout_seconds)
        self.assertIsNone(legacy_decoded.started_at)
        self.assertIsNone(legacy_decoded.finished_at)

        client.include_control_metadata = True
        wire = service.dispatch(base)
        self.assertEqual(wire["timeout_seconds"], 900)
        self.assertEqual(wire["started_at"], "2026-07-31T00:00:00+00:00")
        self.assertEqual(
            wire["finished_at"],
            "2026-07-31T00:00:00.001000+00:00",
        )
        decoded = result_from_dict(json.loads(json.dumps(wire)))
        self.assertEqual(decoded.timeout_seconds, 900)
        self.assertEqual(decoded.started_at, wire["started_at"])
        self.assertEqual(decoded.finished_at, wire["finished_at"])

        forged = json.loads(json.dumps(base))
        forged["params"]["analysis_root"] = "/tmp/attacker"
        with self.assertRaisesRegex(SandboxError, "invalid parameter schema"):
            service.dispatch(forged)


if __name__ == "__main__":
    unittest.main()
