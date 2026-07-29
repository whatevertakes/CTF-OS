from __future__ import annotations

import builtins
import errno
import hashlib
import inspect
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from csv import reader
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import ctf_os.sandbox.daemon as sandbox_daemon
import ctf_os.sandbox.files as sandbox_files
from ctf_os.container_tools import GPUPlan
from ctf_os.director.resources import ResourceVector, tool_profile
from ctf_os.engine.flags import (
    FLAG_CANDIDATE_SIDECAR,
    PROOF_LIVE_DIRECTORY,
)
from ctf_os.sandbox.client import (
    LocalChallengeSandboxClient,
    UnixChallengeSandboxClient,
    command_from_dict,
    command_to_dict,
)
from ctf_os.sandbox.daemon import (
    CapabilityAuthority,
    CapabilityError,
    SandboxService,
    UnixSandboxServer,
)
from ctf_os.sandbox.docker import DockerLimits, DockerSandboxBackend
from ctf_os.sandbox.files import (
    SafeFileError,
    WorkTreeLimitError,
    copy_bounded_regular,
    measure_work_tree,
)
from ctf_os.sandbox.types import (
    BackgroundJobUnsupported,
    ChallengeScope,
    CommandSpec,
    JobRef,
    NetworkDenied,
    NetworkPolicy,
    NetworkTarget,
    ProofInput,
    SandboxError,
    SandboxResult,
    ScopeError,
    ensure_foreground_command,
)

IMAGE_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class _ArtifactOnlyBackend:
    def __init__(self, scope: ChallengeScope) -> None:
        self.scope = scope


class _FakeClient:
    def __init__(self, fingerprint: str) -> None:
        self._fingerprint = fingerprint

    @property
    def scope_fingerprint(self) -> str:
        return self._fingerprint

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds
        return None

    def run(self, spec):
        return SandboxResult(
            run_id="run-00000001",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary="ok",
            stderr_summary="",
            stdout_bytes=2,
            stderr_bytes=0,
            stdout_path="/work/.ctf/runs/run-00000001/stdout.log",
            stderr_path="/work/.ctf/runs/run-00000001/stderr.log",
        )

    def start_job(self, spec, *, name=None):
        return JobRef("job-00000001", self._fingerprint)

    def job_status(self, ref):
        raise AssertionError("cross-scope request reached backend")

    def job_log(self, ref, *, tail_bytes=8192):
        raise AssertionError("cross-scope request reached backend")

    def cancel_job(self, ref, *, grace_seconds=3):
        raise AssertionError("cross-scope request reached backend")

    def register_artifact(self, locator, *, maximum_bytes):
        raise NotImplementedError

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        del input_locators, proof_inputs
        return self.run(spec)


class SandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.challenge_a = self.root / "challenge-a"
        self.challenge_b = self.root / "challenge-b"
        self.work_a = self.root / "work-a"
        self.work_b = self.root / "work-b"
        self.challenge_a.mkdir()
        self.challenge_b.mkdir()
        self.scope_a = ChallengeScope(
            "a",
            self.challenge_a,
            self.work_a,
            contest_id="contest",
            category="pwn",
        )
        self.scope_b = ChallengeScope(
            "b",
            self.challenge_b,
            self.work_b,
            contest_id="contest",
            category="web",
        )

    def test_unix_client_timeout_bounds_reject_nonfinite_and_boolean_values(
        self,
    ) -> None:
        invalid_rpc_timeouts = (
            None,
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        )
        for timeout in invalid_rpc_timeouts:
            with (
                self.subTest(rpc_timeout=timeout),
                self.assertRaisesRegex(ValueError, "rpc_timeout"),
            ):
                UnixChallengeSandboxClient(
                    self.root / "missing.sock",
                    "token",
                    self.scope_a.fingerprint,
                    rpc_timeout=timeout,  # type: ignore[arg-type]
                )

        client = UnixChallengeSandboxClient(
            self.root / "missing.sock",
            "token",
            self.scope_a.fingerprint,
        )
        for timeout in (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        ):
            with (
                self.subTest(call_timeout=timeout),
                self.assertRaisesRegex(SandboxError, "RPC timeout"),
            ):
                client._call(
                    "synthetic",
                    {},
                    timeout=timeout,  # type: ignore[arg-type]
                )

        ref = JobRef(
            "job-00000001",
            self.scope_a.fingerprint,
        )
        for grace_seconds in (
            True,
            -1,
            31,
            float("nan"),
            float("inf"),
            "1",
        ):
            with (
                self.subTest(grace_seconds=grace_seconds),
                self.assertRaisesRegex(ValueError, "grace_seconds"),
            ):
                client.cancel_job(
                    ref,
                    grace_seconds=grace_seconds,  # type: ignore[arg-type]
                )

    def test_capability_secret_partial_write_completes_exact_payload(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        real_open = builtins.open
        write_calls = 0

        class PartialFirstWrite:
            def __init__(self, stream) -> None:
                self.stream = stream

            def fileno(self) -> int:
                return self.stream.fileno()

            def write(self, payload) -> int:
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    return self.stream.write(payload[:11])
                return self.stream.write(payload)

            def close(self) -> None:
                self.stream.close()

        def partial_open(*args, **kwargs):
            return PartialFirstWrite(real_open(*args, **kwargs))

        with patch.object(
            sandbox_daemon.builtins,
            "open",
            side_effect=partial_open,
        ):
            created = CapabilityAuthority.from_file(secret_path)

        loaded = CapabilityAuthority.from_file(secret_path)
        self.assertGreaterEqual(write_calls, 2)
        self.assertEqual(secret_path.stat().st_size, 32)
        self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(created._secret, loaded._secret)

    def test_capability_secret_is_private_at_initial_creation(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        real_os_open = sandbox_daemon.os.open
        creation_modes: list[int] = []

        def inspect_open(path, flags, mode=0o777, *args, **kwargs):
            descriptor = real_os_open(path, flags, mode, *args, **kwargs)
            if flags & os.O_CREAT:
                creation_modes.append(
                    os.fstat(descriptor).st_mode & 0o777
                )
            return descriptor

        previous_umask = os.umask(0)
        try:
            with patch.object(
                sandbox_daemon.os,
                "open",
                side_effect=inspect_open,
            ):
                created = CapabilityAuthority.from_file(secret_path)
        finally:
            os.umask(previous_umask)

        loaded = CapabilityAuthority.from_file(secret_path)
        self.assertEqual(creation_modes, [0o600])
        self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(created._secret, loaded._secret)

    def test_capability_secret_short_read_loads_the_exact_full_key(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        secret_path.parent.mkdir(parents=True)
        secret = bytes(range(64))
        secret_path.write_bytes(secret)
        secret_path.chmod(0o600)
        real_read = sandbox_daemon.os.read
        shortened = False

        def read_half_once(descriptor, requested):
            nonlocal shortened
            if not shortened:
                shortened = True
                return real_read(
                    descriptor,
                    min(requested, len(secret) // 2),
                )
            return real_read(descriptor, requested)

        with patch.object(
            sandbox_daemon.os,
            "read",
            side_effect=read_half_once,
        ):
            issuer = CapabilityAuthority.from_file(secret_path)
        verifier = CapabilityAuthority.from_file(secret_path)
        token = issuer.issue(self.scope_a.fingerprint)

        self.assertTrue(shortened)
        self.assertEqual(issuer._secret, secret)
        self.assertEqual(verifier._secret, secret)
        self.assertEqual(
            verifier.verify(token),
            self.scope_a.fingerprint,
        )

    def test_capability_secret_concurrent_change_fails_closed(self) -> None:
        secret_path = self.root / "daemon" / "secret"
        secret_path.parent.mkdir(parents=True)
        secret_path.write_bytes(bytes(range(64)))
        secret_path.chmod(0o600)
        real_read = sandbox_daemon.os.read
        changed = False

        def read_then_append(descriptor, requested):
            nonlocal changed
            block = real_read(descriptor, min(requested, 32))
            if not changed:
                changed = True
                with secret_path.open("ab") as stream:
                    stream.write(b"x")
            return block

        with (
            patch.object(
                sandbox_daemon.os,
                "read",
                side_effect=read_then_append,
            ),
            self.assertRaisesRegex(
                CapabilityError,
                "changed while being read",
            ),
        ):
            CapabilityAuthority.from_file(secret_path)

        self.assertTrue(changed)

    def test_capability_secret_rejects_truncated_and_nonprivate_files(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        secret_path.parent.mkdir(parents=True)
        for payload, mode in (
            (b"x" * 31, 0o600),
            (b"x" * 32, 0o644),
        ):
            with self.subTest(size=len(payload), mode=oct(mode)):
                secret_path.write_bytes(payload)
                secret_path.chmod(mode)
                with self.assertRaisesRegex(
                    CapabilityError,
                    "private regular file",
                ):
                    CapabilityAuthority.from_file(secret_path)

    def test_capability_secret_zero_write_cleans_and_recovers(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        real_open = builtins.open

        class ZeroWrite:
            def __init__(self, stream) -> None:
                self.stream = stream

            def fileno(self) -> int:
                return self.stream.fileno()

            def write(self, payload) -> int:
                del payload
                return 0

            def close(self) -> None:
                self.stream.close()

        def zero_open(*args, **kwargs):
            return ZeroWrite(real_open(*args, **kwargs))

        with (
            patch.object(
                sandbox_daemon.builtins,
                "open",
                side_effect=zero_open,
            ),
            self.assertRaisesRegex(OSError, "made no progress"),
        ):
            CapabilityAuthority.from_file(secret_path)

        self.assertFalse(secret_path.exists())
        created = CapabilityAuthority.from_file(secret_path)
        loaded = CapabilityAuthority.from_file(secret_path)
        self.assertEqual(secret_path.stat().st_size, 32)
        self.assertEqual(created._secret, loaded._secret)

    def test_capability_secret_zero_write_retries_transient_unlink(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        real_open = builtins.open
        real_unlink = Path.unlink
        unlink_calls = 0

        class ZeroWrite:
            def __init__(self, stream) -> None:
                self.stream = stream

            def fileno(self) -> int:
                return self.stream.fileno()

            def write(self, payload) -> int:
                del payload
                return 0

            def close(self) -> None:
                self.stream.close()

        def zero_open(*args, **kwargs):
            return ZeroWrite(real_open(*args, **kwargs))

        def transient_unlink(path, *args, **kwargs):
            nonlocal unlink_calls
            if path == secret_path:
                unlink_calls += 1
                if unlink_calls == 1:
                    raise OSError("synthetic transient secret unlink failure")
            return real_unlink(path, *args, **kwargs)

        with (
            patch.object(
                sandbox_daemon.builtins,
                "open",
                side_effect=zero_open,
            ),
            patch.object(
                Path,
                "unlink",
                autospec=True,
                side_effect=transient_unlink,
            ),
            self.assertRaisesRegex(OSError, "made no progress"),
        ):
            CapabilityAuthority.from_file(secret_path)

        self.assertEqual(unlink_calls, 2)
        self.assertFalse(secret_path.exists())
        created = CapabilityAuthority.from_file(secret_path)
        loaded = CapabilityAuthority.from_file(secret_path)
        self.assertEqual(created._secret, loaded._secret)

    def test_capability_secret_create_race_does_not_clobber_winner(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        secret_path.parent.mkdir(parents=True)
        winner = os.urandom(32)
        secret_path.write_bytes(winner)
        secret_path.chmod(0o600)
        real_os_open = sandbox_daemon.os.open
        open_calls = 0

        def miss_then_open(*args, **kwargs):
            nonlocal open_calls
            open_calls += 1
            if open_calls == 1:
                raise FileNotFoundError
            return real_os_open(*args, **kwargs)

        with (
            patch.object(
                sandbox_daemon.os,
                "open",
                side_effect=miss_then_open,
            ),
            self.assertRaises(FileExistsError),
        ):
            CapabilityAuthority.from_file(secret_path)

        self.assertEqual(open_calls, 2)
        self.assertEqual(secret_path.read_bytes(), winner)
        self.assertEqual(secret_path.stat().st_mode & 0o777, 0o600)

    def test_capability_secret_allocation_interrupt_cleans_and_recovers(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"

        def fd_targets() -> dict[int, str]:
            targets: dict[int, str] = {}
            for raw_descriptor in os.listdir("/proc/self/fd"):
                try:
                    descriptor = int(raw_descriptor)
                    targets[descriptor] = os.readlink(
                        f"/proc/self/fd/{descriptor}"
                    )
                except (OSError, ValueError):
                    pass
            return targets

        for interruption in (
            KeyboardInterrupt("synthetic capability allocation interrupt"),
            SystemExit(37),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                injected = False
                before_fds = fd_targets()

                def profile(_frame, event, argument):
                    nonlocal injected
                    if (
                        event == "c_return"
                        and argument is builtins.open
                        and not injected
                    ):
                        injected = True
                        raise interruption

                previous_profile = sys.getprofile()
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", ResourceWarning)
                        sys.setprofile(profile)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            CapabilityAuthority.from_file(secret_path)
                finally:
                    sys.setprofile(previous_profile)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertEqual(fd_targets(), before_fds)
                self.assertFalse(secret_path.exists())
                created = CapabilityAuthority.from_file(secret_path)
                loaded = CapabilityAuthority.from_file(secret_path)
                self.assertEqual(created._secret, loaded._secret)
                secret_path.unlink()

    def test_capability_secret_write_interrupt_cleans_and_recovers(
        self,
    ) -> None:
        secret_path = self.root / "daemon" / "secret"
        real_open = builtins.open

        for interruption in (
            KeyboardInterrupt("synthetic capability write interrupt"),
            SystemExit(38),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                class InterruptingWrite:
                    def __init__(self, stream) -> None:
                        self.stream = stream

                    def fileno(self) -> int:
                        return self.stream.fileno()

                    def write(self, payload) -> int:
                        self.stream.write(payload[:7])
                        raise interruption

                    def close(self) -> None:
                        self.stream.close()

                def interrupting_open(*args, **kwargs):
                    return InterruptingWrite(real_open(*args, **kwargs))

                with (
                    patch.object(
                        sandbox_daemon.builtins,
                        "open",
                        side_effect=interrupting_open,
                    ),
                    self.assertRaises(
                        type(interruption)
                    ) as raised,
                ):
                    CapabilityAuthority.from_file(secret_path)

                self.assertIs(raised.exception, interruption)
                self.assertFalse(secret_path.exists())
                created = CapabilityAuthority.from_file(secret_path)
                loaded = CapabilityAuthority.from_file(secret_path)
                self.assertEqual(created._secret, loaded._secret)
                secret_path.unlink()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_scope_rejects_overlapping_challenge_and_work(self) -> None:
        with self.assertRaises(ScopeError):
            ChallengeScope(
                "bad",
                self.challenge_a,
                self.challenge_a / "work",
            )

    def test_scope_accepts_literal_unicode_and_spaces(self) -> None:
        scope = ChallengeScope(
            "두 번째 문제",
            self.challenge_a,
            self.work_a,
            contest_id="Demo CTF",
            category="웹 해킹",
        )
        self.assertEqual(scope.contest_id, "Demo CTF")
        self.assertEqual(scope.category, "웹 해킹")
        self.assertEqual(scope.challenge_id, "두 번째 문제")
        self.assertRegex(scope.fingerprint, r"^[0-9a-f]{64}$")

    def test_scope_rejects_control_and_path_components(self) -> None:
        for challenge_id in ("..", "bad/name", "bad\\name", "bad\nname", "\x00"):
            with self.subTest(challenge_id=challenge_id), self.assertRaises(
                ScopeError
            ):
                ChallengeScope(
                    challenge_id,
                    self.challenge_a,
                    self.work_a,
                )

    def test_default_network_is_deny_and_allowlist_is_explicit(self) -> None:
        policy = NetworkPolicy.deny_all()
        self.assertEqual(policy.authorize(None), "none")
        with self.assertRaises(NetworkDenied):
            policy.authorize(NetworkTarget("ctf.example", 443))

        policy = NetworkPolicy.allow(
            ["https://ctf.example:443"],
            docker_network="ctf-egress",
            enforcement="proxy",
        )
        self.assertEqual(
            policy.authorize(NetworkTarget("ctf.example", 443, "https")),
            "ctf-egress",
        )
        with self.assertRaises(NetworkDenied):
            policy.authorize(NetworkTarget("other.example", 443, "https"))

        declared = NetworkPolicy.allow(
            ["https://ctf.example:443"],
            docker_network="bridge",
            enforcement="declared",
        )
        with self.assertRaisesRegex(NetworkDenied, "not an egress boundary"):
            declared.authorize(
                NetworkTarget("ctf.example", 443, "https")
            )
        with self.assertRaisesRegex(ValueError, "dedicated restricted"):
            NetworkPolicy.allow(
                ["https://ctf.example:443"],
                docker_network="bridge",
                enforcement="proxy",
            )

    def test_docker_shape_has_fixed_readonly_challenge_and_writable_work(self) -> None:
        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(
                cpus=2,
                memory_mib=4096,
                pids=512,
                ptrace=False,
            ),
        )
        argv = backend.build_container_argv(network="none")
        self.assertIn("none", argv)
        self.assertIn("--read-only", argv)
        challenge_mount = next(
            value for value in argv if "dst=/challenge" in value
        )
        work_mount = next(value for value in argv if "dst=/work" in value)
        self.assertIn(str(self.challenge_a), challenge_mount)
        self.assertIn("readonly", challenge_mount)
        self.assertIn(str(self.work_a), work_mount)
        self.assertNotIn("readonly", work_mount)
        self.assertEqual(argv[-2:], ["ctf-idle", "--serve"])

    def test_docker_mounts_preserve_commas_and_quotes_in_host_paths(self) -> None:
        challenge = self.root / 'challenge,with"quote'
        work = self.root / "work,with,commas"
        challenge.mkdir()
        scope = ChallengeScope(
            "quoted-mount",
            challenge,
            work,
            contest_id="contest",
            category="misc",
        )

        argv = DockerSandboxBackend(scope).build_container_argv(network="none")
        specifications = [
            argv[index + 1]
            for index, argument in enumerate(argv[:-1])
            if argument == "--mount"
        ]
        decoded = [next(reader([value])) for value in specifications]

        self.assertEqual(decoded[0][0], "type=bind")
        self.assertIn(f"src={challenge}", decoded[0])
        self.assertIn("dst=/challenge", decoded[0])
        self.assertIn("readonly", decoded[0])
        self.assertIn(f"src={work}", decoded[1])
        self.assertIn("dst=/work", decoded[1])

    def test_pinned_image_is_the_effective_reference_and_verified_identity(
        self,
    ) -> None:
        backend = DockerSandboxBackend(
            self.scope_a,
            image="ctf-os:core",
            image_digest=IMAGE_DIGEST,
        )
        argv = backend.build_container_argv(
            network="none",
            command=("true",),
        )
        self.assertEqual(argv[-2:], [IMAGE_DIGEST, "true"])
        self.assertIn("ctfos.image=ctf-os:core", argv)
        self.assertIn(f"ctfos.image_digest={IMAGE_DIGEST}", argv)

        details = {
            "Config": {
                "Labels": {
                    "ctfos.managed": "true",
                    "ctfos.scope": self.scope_a.fingerprint,
                    "ctfos.network": "none",
                    "ctfos.image": "ctf-os:core",
                    "ctfos.image_digest": IMAGE_DIGEST,
                },
                "Image": IMAGE_DIGEST,
            },
            "Image": IMAGE_DIGEST,
            "Mounts": [
                {
                    "Source": str(self.challenge_a),
                    "Destination": "/challenge",
                    "RW": False,
                },
                {
                    "Source": str(self.work_a),
                    "Destination": "/work",
                    "RW": True,
                },
            ],
            "State": {"Running": True},
        }
        self.assertTrue(backend._verify_container(details, "none"))
        details["Image"] = OTHER_DIGEST
        with self.assertRaisesRegex(ScopeError, "another scope"):
            backend._verify_container(details, "none")

    def test_command_contract_rejects_unbounded_or_empty_calls(self) -> None:
        with self.assertRaises(ValueError):
            CommandSpec(())
        with self.assertRaises(ValueError):
            CommandSpec(("true",), summary_bytes=65537)
        with self.assertRaises(ValueError):
            CommandSpec(("true",), environment={"BAD-NAME": "x"})
        for invalid_deadline in (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
        ):
            with self.subTest(deadline=invalid_deadline):
                with self.assertRaisesRegex(
                    ValueError,
                    "deadline_monotonic_seconds",
                ):
                    CommandSpec(
                        ("true",),
                        deadline_monotonic_seconds=invalid_deadline,
                    )

        deadline = 2_000_000_002.0
        restored = command_from_dict(
            command_to_dict(
                CommandSpec(
                    ("true",),
                    deadline_monotonic_seconds=deadline,
                )
            )
        )
        self.assertEqual(restored.deadline_monotonic_seconds, deadline)

    def test_work_tree_measurement_does_not_follow_symlinks(self) -> None:
        outside = self.root / "outside-sparse"
        with outside.open("wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        (self.work_a / "outside-link").symlink_to(outside)

        usage = measure_work_tree(self.work_a, maximum_bytes=1024 * 1024)

        self.assertEqual(usage.entries, 1)
        self.assertLess(usage.accounted_bytes, 1024 * 1024)
        self.assertLess(usage.logical_bytes, outside.stat().st_size)

    def test_work_tree_measurement_charges_sparse_logical_length(self) -> None:
        sparse = self.work_a / "sparse.bin"
        with sparse.open("wb") as handle:
            handle.truncate(8 * 1024 * 1024)

        with self.assertRaisesRegex(
            WorkTreeLimitError,
            "accounted byte limit",
        ):
            measure_work_tree(self.work_a, maximum_bytes=1024 * 1024)

    def test_work_tree_entry_limit_stops_scandir_at_cap_plus_one(self) -> None:
        tree = self.root / "bounded-tree"
        first = tree / "a-first"
        second = tree / "z-second"
        first.mkdir(parents=True)
        second.mkdir()
        for index in range(10):
            (first / f"entry-{index:02d}").touch()

        original_scandir = os.scandir
        consumed = 0

        class CountingScandir:
            def __init__(self, iterator) -> None:
                self.iterator = iterator

            def __enter__(self):
                self.iterator.__enter__()
                return self

            def __exit__(self, exception_type, exception, traceback):
                return self.iterator.__exit__(
                    exception_type,
                    exception,
                    traceback,
                )

            def __iter__(self):
                return self

            def __next__(self):
                nonlocal consumed
                entry = next(self.iterator)
                consumed += 1
                return entry

        def counting_scandir(path):
            return CountingScandir(original_scandir(path))

        with (
            patch.object(sandbox_files, "MAX_WORK_TREE_ENTRIES", 4),
            patch.object(
                sandbox_files.os,
                "scandir",
                side_effect=counting_scandir,
            ),
            self.assertRaisesRegex(
                SafeFileError,
                "work tree exceeds 4 entries",
            ),
        ):
            measure_work_tree(tree, maximum_bytes=1024 * 1024)

        self.assertEqual(consumed, 5)

    def test_work_tree_measurement_fails_on_between_pass_mutation(self) -> None:
        original_scan = sandbox_files._scan_work_tree_once
        scan_count = 0

        def scan_then_mutate(root, maximum_bytes):
            nonlocal scan_count
            snapshot = original_scan(root, maximum_bytes)
            scan_count += 1
            if scan_count == 1:
                (Path(root) / "raced.txt").write_text(
                    "changed",
                    encoding="utf-8",
                )
            return snapshot

        with patch.object(
            sandbox_files,
            "_scan_work_tree_once",
            side_effect=scan_then_mutate,
        ), self.assertRaisesRegex(
            SafeFileError,
            "between accounting passes",
        ):
            measure_work_tree(self.work_a, maximum_bytes=1024 * 1024)

    def test_work_tree_guard_handoffs_do_not_strand_the_lock(self) -> None:
        def run_handoff_case(
            boundary: str,
            interruption: BaseException,
        ) -> None:
            backend = DockerSandboxBackend(self.scope_a)
            guard = backend._work_tree_guard(
                self.work_a,
                operation="interrupted operation",
            )
            handoff_method = (
                guard.__enter__
                if boundary == "enter"
                else guard.start
            )
            handoff_code = handoff_method.__code__

            def interrupt_return(frame, event, _argument):
                if (
                    frame.f_code is handoff_code
                    and event == "return"
                    and frame.f_locals.get("self") is guard
                ):
                    sys.settrace(None)
                    raise interruption
                return interrupt_return

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_return)
                with (
                    self.assertRaises(
                        type(interruption)
                    ) as raised,
                    guard as active_guard,
                ):
                    active_guard.start()
            finally:
                sys.settrace(previous_trace)

            self.assertIs(raised.exception, interruption)
            self.assertFalse(guard._acquired)
            completed = threading.Event()
            thread_errors: list[Exception] = []

            def use_next_guard() -> None:
                try:
                    with backend._work_tree_guard(
                        self.work_a,
                        operation="recovery operation",
                    ) as next_guard:
                        next_guard.start()
                    completed.set()
                except (OSError, RuntimeError) as error:
                    thread_errors.append(error)

            next_thread = threading.Thread(
                target=use_next_guard,
                daemon=True,
            )
            next_thread.start()
            next_thread.join(timeout=1)

            self.assertFalse(next_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertTrue(completed.is_set())

        for boundary in ("enter", "start"):
            for interruption in (
                KeyboardInterrupt(f"synthetic guard {boundary} interrupt"),
                SystemExit(f"synthetic guard {boundary} exit"),
            ):
                with self.subTest(
                    boundary=boundary,
                    interruption=type(interruption).__name__,
                ):
                    run_handoff_case(boundary, interruption)

    def test_work_tree_guard_acquire_handoff_releases_the_lock(self) -> None:
        backend = DockerSandboxBackend(self.scope_a)
        real_lock = backend._work_tree_lock
        interruption = KeyboardInterrupt(
            "synthetic work-tree lock acquire handoff interrupt"
        )

        class InterruptAfterAcquire:
            def __init__(self) -> None:
                self.interrupted = False

            def _is_owned(self):
                return real_lock._is_owned()

            def acquire(self, *args, **kwargs):
                result = real_lock.acquire(*args, **kwargs)
                if not self.interrupted:
                    self.interrupted = True
                    raise interruption
                return result

            def release(self):
                return real_lock.release()

        backend._work_tree_lock = InterruptAfterAcquire()
        guard = backend._work_tree_guard(
            self.work_a,
            operation="interrupted acquire",
        )
        with (
            self.assertRaises(KeyboardInterrupt) as raised,
            guard as active_guard,
        ):
            active_guard.start()

        self.assertIs(raised.exception, interruption)
        self.assertFalse(guard._release_maybe_needed)
        self.assertFalse(guard._acquired)

        completed = threading.Event()

        def use_next_guard() -> None:
            with backend._work_tree_guard(
                self.work_a,
                operation="acquire recovery",
            ) as next_guard:
                next_guard.start()
            completed.set()

        next_thread = threading.Thread(
            target=use_next_guard,
            daemon=True,
        )
        next_thread.start()
        next_thread.join(timeout=1)

        self.assertFalse(next_thread.is_alive())
        self.assertTrue(completed.is_set())

    def test_work_tree_guard_started_store_interrupt_releases_the_lock(
        self,
    ) -> None:
        def run_case(interruption: BaseException) -> None:
            backend = DockerSandboxBackend(self.scope_a)
            guard = backend._work_tree_guard(
                self.work_a,
                operation="started store interrupt",
            )
            source_lines, first_line = inspect.getsourcelines(guard.start)
            started_store_line = next(
                first_line + index
                for index, source_line in enumerate(source_lines)
                if source_line.strip() == "self._started = True"
            )
            start_code = guard.start.__code__

            def interrupt_started_store(frame, event, _argument):
                if (
                    frame.f_code is start_code
                    and event == "line"
                    and frame.f_lineno == started_store_line
                    and frame.f_locals.get("self") is guard
                ):
                    sys.settrace(None)
                    raise interruption
                return interrupt_started_store

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_started_store)
                with (
                    self.assertRaises(
                        type(interruption)
                    ) as raised,
                    guard as active_guard,
                ):
                    active_guard.start()
            finally:
                sys.settrace(previous_trace)

            self.assertIs(raised.exception, interruption)
            self.assertFalse(guard._started)
            self.assertFalse(guard._release_maybe_needed)
            self.assertFalse(guard._acquired)

            completed = threading.Event()
            thread_errors: list[BaseException] = []

            def use_next_guard() -> None:
                try:
                    with backend._work_tree_guard(
                        self.work_a,
                        operation="started store recovery",
                    ) as next_guard:
                        next_guard.start()
                    completed.set()
                except BaseException as error:
                    thread_errors.append(error)

            next_thread = threading.Thread(
                target=use_next_guard,
                daemon=True,
            )
            next_thread.start()
            next_thread.join(timeout=1)

            self.assertFalse(next_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertTrue(completed.is_set())

        for interruption in (
            KeyboardInterrupt("synthetic started store interrupt"),
            SystemExit("synthetic started store exit"),
        ):
            with self.subTest(
                interruption=type(interruption).__name__,
            ):
                run_case(interruption)

    def test_work_tree_guard_preserves_primary_and_post_errors(self) -> None:
        backend = DockerSandboxBackend(self.scope_a)
        phases: list[str] = []

        def fail_post_check(_work_dir=None, *, phase):
            phases.append(phase)
            if phase.startswith("after "):
                raise SandboxError("synthetic post-check failure")

        primary_error = ValueError("synthetic primary failure")
        with (
            patch.object(
                backend,
                "check_work_tree",
                side_effect=fail_post_check,
            ),
            self.assertRaisesRegex(
                SandboxError,
                (
                    "synthetic primary failure; additionally, "
                    "synthetic post-check failure"
                ),
            ) as raised,
            backend._work_tree_guard(
                self.work_a,
                operation="failing operation",
            ) as guard,
        ):
            guard.start()
            raise primary_error

        self.assertIs(raised.exception.__cause__, primary_error)
        self.assertEqual(
            phases,
            [
                "before failing operation",
                "after failing operation",
            ],
        )
        self.assertFalse(guard._acquired)

    def test_work_tree_limit_blocks_docker_before_execution(self) -> None:
        with (self.work_a / "already-large").open("wb") as handle:
            handle.truncate(8192)
        calls: list[list[str]] = []

        def forbidden_runner(command, **_kwargs):
            calls.append(command)
            raise AssertionError("pre-check must reject before Docker")

        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(work_tree_max_bytes=4096),
            runner=forbidden_runner,
        )
        with self.assertRaisesRegex(SandboxError, "before sandbox command"):
            backend.run(CommandSpec(("true",)))
        self.assertEqual(calls, [])

    def test_work_tree_limit_fails_after_one_shot_and_bounds_streams(
        self,
    ) -> None:
        calls: list[list[str]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def oversized_runner(command, **_kwargs):
            calls.append(command)
            with (self.work_a / "new-sparse").open("wb") as handle:
                handle.truncate(8192)
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(work_tree_max_bytes=4096),
            runner=oversized_runner,
        )
        with self.assertRaisesRegex(SandboxError, "after sandbox command"):
            backend.run(CommandSpec(("true",)))

        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertIn("--rm", command)
        self.assertEqual(
            command[command.index("--stdout-limit-bytes") + 1],
            "1024",
        )
        self.assertEqual(
            command[command.index("--stderr-limit-bytes") + 1],
            "1024",
        )

    def test_background_start_is_rejected_before_docker_or_rpc(self) -> None:
        docker_calls: list[object] = []

        def forbidden_runner(*args, **kwargs):
            docker_calls.append((args, kwargs))
            raise AssertionError("background rejection must happen before Docker")

        backend = DockerSandboxBackend(self.scope_a, runner=forbidden_runner)
        with self.assertRaises(BackgroundJobUnsupported):
            backend.start_job(CommandSpec(("sleep", "60")))
        with self.assertRaises(BackgroundJobUnsupported):
            backend.run(CommandSpec(("ctf-bg", "--", "sleep", "60")))
        with self.assertRaises(BackgroundJobUnsupported):
            backend.run(
                CommandSpec(
                    ("sh", "-c", "ctf-bg -- sleep 60"),
                )
            )
        self.assertEqual(docker_calls, [])

        # Long foreground calls and existing job controls remain legal.
        ensure_foreground_command(("sleep", "60"))
        ensure_foreground_command(("ctf-jobs", "--json"))
        ensure_foreground_command(("ctf-log", "--json", "job-00000001"))
        ensure_foreground_command(("ctf-kill", "--json", "job-00000001"))

    def test_foreground_run_uses_one_shot_container_supervision(self) -> None:
        calls: list[list[str]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "ok",
            "stderr_summary": "",
            "stdout_bytes": 2,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        result = backend.run(CommandSpec(("sleep", "1")))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertEqual(command[:2], ["docker", "run"])
        self.assertIn("--rm", command)
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("ctfwrap", command)
        self.assertNotIn("exec", command[:3])

    def test_one_shot_hard_deadline_bounds_container_and_command(self) -> None:
        calls: list[tuple[list[str], float]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs["timeout"]))
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with (
            patch("ctf_os.sandbox.docker.time.time", return_value=1_000.0),
            patch(
                "ctf_os.sandbox.docker.time.monotonic",
                return_value=200.0,
            ),
        ):
            backend.run(
                CommandSpec(
                    ("true",),
                    timeout_seconds=30,
                    deadline_monotonic_seconds=202.0,
                )
            )

        self.assertEqual(len(calls), 1)
        command, host_timeout = calls[0]
        self.assertEqual(host_timeout, 2.0)
        ctfwrap_index = command.index("ctfwrap")
        timeout_index = command.index("--timeout", ctfwrap_index)
        self.assertEqual(command[timeout_index + 1], "2")

        clock = [200.0]

        def late_runner(command, **_kwargs):
            clock[0] = 203.0
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        late_backend = DockerSandboxBackend(
            self.scope_a,
            runner=late_runner,
        )
        with (
            patch(
                "ctf_os.sandbox.docker.time.monotonic",
                side_effect=lambda: clock[0],
            ),
            self.assertRaisesRegex(
                SandboxError,
                "deadline expired before sandbox result promotion",
            ),
        ):
            late_backend.run(
                CommandSpec(
                    ("true",),
                    timeout_seconds=30,
                    deadline_monotonic_seconds=202.0,
                )
            )

    def test_one_shot_real_local_process_cannot_outlive_hard_deadline(
        self,
    ) -> None:
        cleanup_calls: list[list[str]] = []

        def local_process_runner(command, **kwargs):
            if command[:4] == ["docker", "container", "rm", "--force"]:
                cleanup_calls.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(10)",
                ],
                **kwargs,
            )

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=local_process_runner,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(
            SandboxError,
            "Docker control operation timed out",
        ):
            backend.run(
                CommandSpec(
                    ("sleep", "10"),
                    timeout_seconds=30,
                    deadline_monotonic_seconds=time.monotonic() + 2.0,
                )
            )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 4.0)
        self.assertEqual(len(cleanup_calls), 1)

    def test_one_shot_control_timeout_removes_only_exact_generated_container(
        self,
    ) -> None:
        calls: list[list[str]] = []

        def timeout_then_cleanup(command, **kwargs):
            calls.append(command)
            if command[:2] == ["docker", "run"]:
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            if command[:4] == ["docker", "container", "rm", "--force"]:
                return subprocess.CompletedProcess(command, 0, command[-1] + "\n", "")
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=timeout_then_cleanup,
        )
        with self.assertRaisesRegex(
            SandboxError, "Docker control operation timed out"
        ):
            backend.run(CommandSpec(("sleep", "1"), timeout_seconds=1))

        self.assertEqual(len(calls), 2)
        run_command, cleanup_command = calls
        generated_name = run_command[run_command.index("--name") + 1]
        self.assertRegex(
            generated_name,
            (
                rf"^ctfos-run-{self.scope_a.fingerprint[:12]}-"
                r"[0-9a-f]{12}$"
            ),
        )
        self.assertEqual(
            cleanup_command,
            ["docker", "container", "rm", "--force", generated_name],
        )
        self.assertNotIn("*", cleanup_command)

    def test_one_shot_timeout_cleanup_control_interrupt_retries_exact_name(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic timeout cleanup interrupt"),
            SystemExit(31),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                calls: list[list[str]] = []
                live_containers: set[str] = set()
                cleanup_attempts = 0
                control_timeouts: list[subprocess.TimeoutExpired] = []

                def timeout_then_interrupted_cleanup(command, **kwargs):
                    nonlocal cleanup_attempts
                    calls.append(list(command))
                    if command[:2] == ["docker", "run"]:
                        generated_name = command[
                            command.index("--name") + 1
                        ]
                        live_containers.add(generated_name)
                        timeout = subprocess.TimeoutExpired(
                            command,
                            kwargs["timeout"],
                        )
                        control_timeouts.append(timeout)
                        raise timeout
                    if command[:4] == [
                        "docker",
                        "container",
                        "rm",
                        "--force",
                    ]:
                        cleanup_attempts += 1
                        self.assertIn(command[-1], live_containers)
                        if cleanup_attempts == 1:
                            raise interruption
                        live_containers.remove(command[-1])
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            command[-1] + "\n",
                            "",
                        )
                    raise AssertionError(command)

                backend = DockerSandboxBackend(
                    self.scope_a,
                    runner=timeout_then_interrupted_cleanup,
                )
                with self.assertRaises(
                    type(interruption)
                ) as raised:
                    backend.run(
                        CommandSpec(
                            ("sleep", "1"),
                            timeout_seconds=1,
                        )
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(control_timeouts), 1)
                self.assertIs(
                    interruption.__context__,
                    control_timeouts[0],
                )
                self.assertTrue(
                    any(
                        "exact container cleanup succeeded after "
                        f"{type(interruption).__name__}" in note
                        for note in interruption.__notes__
                    )
                )
                self.assertEqual(live_containers, set())
                self.assertEqual(cleanup_attempts, 2)
                self.assertEqual(len(calls), 3)
                run_command, first_cleanup, second_cleanup = calls
                generated_name = run_command[
                    run_command.index("--name") + 1
                ]
                exact_cleanup = [
                    "docker",
                    "container",
                    "rm",
                    "--force",
                    generated_name,
                ]
                self.assertEqual(first_cleanup, exact_cleanup)
                self.assertEqual(second_cleanup, exact_cleanup)
                self.assertNotIn("*", first_cleanup)

    def test_one_shot_cleanup_stops_after_second_independent_control_signal(
        self,
    ) -> None:
        first_interruption = KeyboardInterrupt(
            "synthetic first cleanup interruption"
        )
        second_interruption = SystemExit(32)
        calls: list[list[str]] = []
        live_containers: set[str] = set()
        cleanup_attempts = 0
        control_timeout: subprocess.TimeoutExpired | None = None

        def timeout_then_twice_interrupted_cleanup(command, **kwargs):
            nonlocal cleanup_attempts, control_timeout
            calls.append(list(command))
            if command[:2] == ["docker", "run"]:
                generated_name = command[
                    command.index("--name") + 1
                ]
                live_containers.add(generated_name)
                control_timeout = subprocess.TimeoutExpired(
                    command,
                    kwargs["timeout"],
                )
                raise control_timeout
            if command[:4] == [
                "docker",
                "container",
                "rm",
                "--force",
            ]:
                cleanup_attempts += 1
                if cleanup_attempts == 1:
                    raise first_interruption
                if cleanup_attempts == 2:
                    raise second_interruption
                self.fail("cleanup exceeded its bounded control retry")
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=timeout_then_twice_interrupted_cleanup,
        )
        with self.assertRaises(KeyboardInterrupt) as raised:
            backend.run(
                CommandSpec(
                    ("sleep", "1"),
                    timeout_seconds=1,
                )
        )

        self.assertIs(raised.exception, first_interruption)
        self.assertIs(
            first_interruption.__context__,
            second_interruption,
        )
        self.assertIs(second_interruption.__context__, control_timeout)
        self.assertEqual(cleanup_attempts, 2)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1], calls[2])
        self.assertEqual(live_containers, {calls[1][-1]})
        self.assertNotIn("*", calls[1])
        self.assertTrue(
            any(
                "retry was interrupted by SystemExit" in note
                for note in first_interruption.__notes__
            )
        )

    def test_one_shot_control_interrupt_removes_only_exact_generated_container(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic container interrupt"),
            SystemExit(23),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                calls: list[list[str]] = []

                def interrupt_then_cleanup(command, **_kwargs):
                    calls.append(command)
                    if command[:2] == ["docker", "run"]:
                        raise interruption
                    if command[:4] == [
                        "docker",
                        "container",
                        "rm",
                        "--force",
                    ]:
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            command[-1] + "\n",
                            "",
                        )
                    raise AssertionError(command)

                backend = DockerSandboxBackend(
                    self.scope_a,
                    runner=interrupt_then_cleanup,
                )
                with self.assertRaises(type(interruption)) as raised:
                    backend.run(
                        CommandSpec(
                            ("sleep", "1"),
                            timeout_seconds=1,
                        )
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(calls), 2)
                run_command, cleanup_command = calls
                generated_name = run_command[
                    run_command.index("--name") + 1
                ]
                self.assertRegex(
                    generated_name,
                    (
                        rf"^ctfos-run-{self.scope_a.fingerprint[:12]}-"
                        r"[0-9a-f]{12}$"
                    ),
                )
                self.assertEqual(
                    cleanup_command,
                    [
                        "docker",
                        "container",
                        "rm",
                        "--force",
                        generated_name,
                    ],
                )
                self.assertNotIn("*", cleanup_command)

    def test_one_shot_interrupt_retries_exact_transient_cleanup(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic transient cleanup interrupt"),
            SystemExit(29),
        ):
            for transient_failure in ("oserror", "nonzero"):
                with self.subTest(
                    interruption=type(interruption).__name__,
                    transient_failure=transient_failure,
                ):
                    self._assert_transient_ephemeral_cleanup_retry(
                        interruption,
                        transient_failure,
                    )

    def _assert_transient_ephemeral_cleanup_retry(
        self,
        interruption: BaseException,
        transient_failure: str,
    ) -> None:
        calls: list[list[str]] = []
        live_containers: set[str] = set()
        cleanup_attempts = 0

        def interrupt_then_retry_cleanup(command, **_kwargs):
            nonlocal cleanup_attempts
            calls.append(list(command))
            if command[:2] == ["docker", "run"]:
                generated_name = command[
                    command.index("--name") + 1
                ]
                live_containers.add(generated_name)
                raise interruption
            if command[:4] == [
                "docker",
                "container",
                "rm",
                "--force",
            ]:
                cleanup_attempts += 1
                self.assertIn(command[-1], live_containers)
                if cleanup_attempts == 1:
                    if transient_failure == "oserror":
                        raise OSError(
                            "synthetic transient cleanup failure"
                        )
                    return subprocess.CompletedProcess(
                        command,
                        1,
                        "",
                        "synthetic transient nonzero",
                    )
                live_containers.remove(command[-1])
                return subprocess.CompletedProcess(
                    command,
                    0,
                    command[-1] + "\n",
                    "",
                )
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=interrupt_then_retry_cleanup,
        )
        with self.assertRaises(type(interruption)) as raised:
            backend.run(
                CommandSpec(
                    ("sleep", "1"),
                    timeout_seconds=1,
                )
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(live_containers, set())
        self.assertEqual(cleanup_attempts, 2)
        run_command, first_cleanup, second_cleanup = calls
        generated_name = run_command[
            run_command.index("--name") + 1
        ]
        exact_cleanup = [
            "docker",
            "container",
            "rm",
            "--force",
            generated_name,
        ]
        self.assertEqual(first_cleanup, exact_cleanup)
        self.assertEqual(second_cleanup, exact_cleanup)
        self.assertNotIn("*", first_cleanup)

    def test_one_shot_oserror_removes_exact_generated_container(
        self,
    ) -> None:
        calls: list[list[str]] = []
        live_containers: set[str] = set()

        def create_then_transport_error(command, **_kwargs):
            calls.append(list(command))
            if command[:2] == ["docker", "run"]:
                generated_name = command[
                    command.index("--name") + 1
                ]
                live_containers.add(generated_name)
                raise OSError("synthetic daemon transport failure")
            if command[:4] == [
                "docker",
                "container",
                "rm",
                "--force",
            ]:
                self.assertIn(command[-1], live_containers)
                live_containers.remove(command[-1])
                return subprocess.CompletedProcess(
                    command,
                    0,
                    command[-1] + "\n",
                    "",
                )
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=create_then_transport_error,
        )
        with self.assertRaisesRegex(
            SandboxError,
            (
                "Docker control operation failed: "
                "synthetic daemon transport failure; "
                "exact container cleanup recovered"
            ),
        ):
            backend.run(
                CommandSpec(("sleep", "1"), timeout_seconds=1)
            )

        self.assertEqual(live_containers, set())
        self.assertEqual(len(calls), 2)
        run_command, cleanup_command = calls
        generated_name = run_command[
            run_command.index("--name") + 1
        ]
        self.assertEqual(
            cleanup_command,
            [
                "docker",
                "container",
                "rm",
                "--force",
                generated_name,
            ],
        )
        self.assertNotIn("*", cleanup_command)

    def test_one_shot_oserror_reports_persistent_exact_cleanup_failure(
        self,
    ) -> None:
        live_containers: set[str] = set()
        cleanup_commands: list[list[str]] = []

        def create_then_fail_cleanup(command, **_kwargs):
            if command[:2] == ["docker", "run"]:
                generated_name = command[
                    command.index("--name") + 1
                ]
                live_containers.add(generated_name)
                raise OSError("synthetic daemon transport failure")
            if command[:4] == [
                "docker",
                "container",
                "rm",
                "--force",
            ]:
                cleanup_commands.append(list(command))
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    "synthetic persistent cleanup denial",
                )
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=create_then_fail_cleanup,
        )
        with self.assertRaisesRegex(
            SandboxError,
            (
                "exact container cleanup failed: "
                "synthetic persistent cleanup denial"
            ),
        ):
            backend.run(
                CommandSpec(("sleep", "1"), timeout_seconds=1)
            )

        self.assertEqual(len(live_containers), 1)
        self.assertEqual(len(cleanup_commands), 2)
        self.assertEqual(cleanup_commands[0], cleanup_commands[1])
        generated_name = next(iter(live_containers))
        self.assertEqual(cleanup_commands[0][-1], generated_name)
        self.assertNotIn("*", cleanup_commands[0])

    def test_one_shot_interrupt_cleanup_failure_preserves_original_error(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("synthetic container interrupt")

        def interrupt_then_fail_cleanup(command, **_kwargs):
            if command[:2] == ["docker", "run"]:
                raise interruption
            if command[:4] == [
                "docker",
                "container",
                "rm",
                "--force",
            ]:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    "synthetic cleanup denial",
                )
            raise AssertionError(command)

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=interrupt_then_fail_cleanup,
        )
        with self.assertRaises(KeyboardInterrupt) as raised:
            backend.run(
                CommandSpec(("sleep", "1"), timeout_seconds=1)
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(
            any(
                "exact container cleanup failed: "
                "synthetic cleanup denial" in note
                for note in interruption.__notes__
            )
        )

    def test_workspace_initialization_is_light_foreground_and_network_denied(
        self,
    ) -> None:
        calls: list[list[str]] = []

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        backend.initialize_workspace()
        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertEqual(command[:2], ["docker", "run"])
        self.assertIn("--rm", command)
        self.assertNotIn("--detach", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--cpus") + 1], "1.0")
        self.assertEqual(command[command.index("--memory") + 1], "2048m")
        self.assertEqual(command[-2:], ["ctf-os:core", "true"])

    def test_workspace_initialization_uses_hard_deadline(self) -> None:
        timeouts: list[float] = []

        def fake_runner(command, **kwargs):
            timeouts.append(kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0, "", "")

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with patch(
            "ctf_os.sandbox.docker.time.monotonic",
            return_value=200.0,
        ):
            backend.initialize_workspace(
                deadline_monotonic_seconds=202.0
            )

        self.assertEqual(timeouts, [2.0])

    def test_foreground_limits_match_light_lease_without_devices(self) -> None:
        calls: list[list[str]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "ok",
            "stderr_summary": "",
            "stdout_bytes": 2,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command, 0, json.dumps(payload), ""
            )

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=fake_runner,
            # Static backend settings must not leak expensive devices into a
            # light per-run resource request.
            limits=DockerLimits(
                cpus=8,
                memory_mib=16 * 1024,
                kvm=True,
                gpu_flags=("--gpus", "all"),
            ),
        )
        backend.run(CommandSpec(("true",)))
        command = calls[0]
        self.assertEqual(command[command.index("--cpus") + 1], "1.0")
        self.assertEqual(command[command.index("--memory") + 1], "2048m")
        self.assertNotIn("/dev/kvm", command)
        self.assertNotIn("--gpus", command)

    def test_gpu_lease_maps_to_exact_limits_and_detected_flags(self) -> None:
        calls: list[list[str]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "ok",
            "stderr_summary": "",
            "stdout_bytes": 2,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command, 0, json.dumps(payload), ""
            )

        backend = DockerSandboxBackend(
            self.scope_a,
            runner=fake_runner,
            gpu_detector=lambda: GPUPlan(
                mode="test",
                detail="test GPU",
                docker_flags=("--gpus", "all"),
            ),
        )
        backend.run(
            CommandSpec(
                ("true",),
                resource_request=tool_profile("gpu"),
            )
        )
        command = calls[0]
        self.assertEqual(command[command.index("--cpus") + 1], "4.0")
        self.assertEqual(command[command.index("--memory") + 1], "10240m")
        self.assertEqual(command[command.index("--gpus") + 1], "all")

    def test_required_gpu_and_kvm_fail_before_docker_when_unavailable(self) -> None:
        docker_calls: list[list[str]] = []

        def forbidden_runner(command, **_kwargs):
            docker_calls.append(command)
            raise AssertionError("missing host device must fail before Docker")

        gpu_backend = DockerSandboxBackend(
            self.scope_a,
            runner=forbidden_runner,
            gpu_detector=lambda: None,
        )
        with self.assertRaisesRegex(SandboxError, "GPU"):
            gpu_backend.run(
                CommandSpec(
                    ("true",),
                    resource_request=tool_profile("gpu"),
                )
            )

        kvm_backend = DockerSandboxBackend(
            self.scope_a,
            runner=forbidden_runner,
            kvm_detector=lambda: False,
        )
        with self.assertRaisesRegex(SandboxError, "KVM"):
            kvm_backend.run(
                CommandSpec(
                    ("true",),
                    resource_request=ResourceVector(
                        cpu=1,
                        memory_mib=2 * 1024,
                        kvm=1,
                    ),
                )
            )
        self.assertEqual(docker_calls, [])

    def test_job_query_does_not_create_a_persistent_idle_runtime(self) -> None:
        calls: list[list[str]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": '{"jobs":[]}',
            "stderr_summary": "",
            "stdout_bytes": 11,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            calls.append(command)
            if command[:3] == ["docker", "container", "inspect"]:
                return subprocess.CompletedProcess(command, 1, "", "not found")
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        result = backend.run(CommandSpec(("ctf-jobs", "--json")))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(calls[0][:3], ["docker", "container", "inspect"])
        self.assertEqual(calls[1][:2], ["docker", "run"])
        self.assertIn("--rm", calls[1])
        self.assertNotIn("--detach", calls[1])

    def test_artifact_registration_is_scoped_and_hashes_content(self) -> None:
        artifact = self.work_a / "artifacts" / "solve.py"
        artifact.parent.mkdir()
        artifact.write_text("print('ok')\n", encoding="utf-8")
        client = LocalChallengeSandboxClient(
            self.scope_a,
            backend=_ArtifactOnlyBackend(self.scope_a),
        )
        reference = client.register_artifact("artifacts/solve.py")
        self.assertEqual(reference.locator, "artifacts/solve.py")
        self.assertEqual(reference.size_bytes, len(b"print('ok')\n"))
        self.assertEqual(reference.scope_fingerprint, self.scope_a.fingerprint)

        outside = self.root / "outside"
        outside.write_text("secret", encoding="utf-8")
        (self.work_a / "escape").symlink_to(outside)
        with self.assertRaises(ScopeError):
            client.register_artifact("escape")
        with self.assertRaises(ScopeError):
            client.register_artifact("../outside")

    def test_artifact_registration_is_capped_by_work_tree_limit(self) -> None:
        artifact = self.work_a / "large-artifact.bin"
        with artifact.open("wb") as handle:
            handle.truncate(8192)
        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(work_tree_max_bytes=4096),
            runner=lambda *_args, **_kwargs: None,
        )
        client = LocalChallengeSandboxClient(self.scope_a, backend=backend)

        with self.assertRaisesRegex(
            ScopeError,
            "workspace pre-check.*accounted byte limit",
        ):
            client.register_artifact(
                "large-artifact.bin",
                maximum_bytes=16 * 1024 * 1024,
            )

    def test_clean_proof_logs_survive_temporary_workspace_cleanup(self) -> None:
        temporary_proof_roots: list[Path] = []
        docker_commands: list[list[str]] = []
        sidecar_payload = (
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "flag_candidate",
                    "stream": "stdout",
                    "value": "KCTF{late_full_stream}",
                }
            ).encode("utf-8")
            + b"\n"
        )

        def fake_runner(command, **_kwargs):
            docker_commands.append(command)
            self.assertIn(IMAGE_DIGEST, command)
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            source_text = next(
                component.removeprefix("src=")
                for component in work_mount.split(",")
                if component.startswith("src=")
            )
            proof_work = Path(source_text)
            temporary_proof_roots.append(proof_work)
            self.assertEqual(
                proof_work.parent,
                self.scope_a.work_dir.parent / PROOF_LIVE_DIRECTORY,
            )
            self.assertNotEqual(proof_work, self.scope_a.work_dir)
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")

            run_id = "run-00000001"
            run_root = proof_work / ".ctf" / "runs" / run_id
            run_root.mkdir(parents=True)
            stdout = b"durable proof stdout\n"
            stderr = b"durable proof stderr\n"
            (run_root / "stdout.log").write_bytes(stdout)
            (run_root / "stderr.log").write_bytes(stderr)
            (run_root / FLAG_CANDIDATE_SIDECAR).write_bytes(
                sidecar_payload
            )
            value = {
                "schema_version": 1,
                "kind": "run_result",
                "run_id": run_id,
                "status": "completed",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 1,
                "stdout_summary": stdout.decode(),
                "stderr_summary": stderr.decode(),
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "stdout_path": f"/work/.ctf/runs/{run_id}/stdout.log",
                "stderr_path": f"/work/.ctf/runs/{run_id}/stderr.log",
            }
            (run_root / "result.json").write_text(
                json.dumps(value),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(value),
                "",
            )

        backend = DockerSandboxBackend(
            self.scope_a,
            image_digest=IMAGE_DIGEST,
            runner=fake_runner,
        )
        result = backend.run_clean_proof(CommandSpec(("true",)))

        self.assertEqual(len(docker_commands), 2)
        self.assertTrue(temporary_proof_roots)
        self.assertTrue(
            all(not path.exists() for path in temporary_proof_roots),
            "TemporaryDirectory must be gone before durability is asserted",
        )
        for locator, expected in (
            (result.stdout_path, b"durable proof stdout\n"),
            (result.stderr_path, b"durable proof stderr\n"),
        ):
            self.assertTrue(locator.startswith("/work/proof/clean-"))
            relative = Path(locator.removeprefix("/work/"))
            durable = (self.scope_a.work_dir / relative).resolve(strict=True)
            self.assertIn(self.scope_a.work_dir, durable.parents)
            self.assertEqual(durable.read_bytes(), expected)
        proof_directory = (
            self.scope_a.work_dir
            / Path(result.stdout_path.removeprefix("/work/")).parent
        )
        self.assertTrue((proof_directory / "result.json").is_file())
        self.assertEqual(
            (proof_directory / FLAG_CANDIDATE_SIDECAR).read_bytes(),
            sidecar_payload,
        )
        self.assertLessEqual(
            (proof_directory / FLAG_CANDIDATE_SIDECAR).stat().st_size,
            1024 * 1024,
        )

    def test_clean_proof_recomputes_command_timeout_after_init(self) -> None:
        clock = [200.0]
        calls: list[tuple[list[str], float]] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs["timeout"]))
            if "ctfwrap" not in command:
                clock[0] += 0.75
                return subprocess.CompletedProcess(command, 0, "", "")
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            run_root = proof_work / ".ctf" / "runs" / "run-00000001"
            run_root.mkdir(parents=True)
            (run_root / "stdout.log").write_bytes(b"")
            (run_root / "stderr.log").write_bytes(b"")
            (run_root / "result.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with patch(
            "ctf_os.sandbox.docker.time.monotonic",
            side_effect=lambda: clock[0],
        ):
            backend.run_clean_proof(
                CommandSpec(
                    ("true",),
                    timeout_seconds=30,
                    deadline_monotonic_seconds=202.0,
                )
            )

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1], 2.0)
        self.assertEqual(calls[1][1], 1.25)
        command = calls[1][0]
        ctfwrap_index = command.index("ctfwrap")
        timeout_index = command.index("--timeout", ctfwrap_index)
        self.assertEqual(command[timeout_index + 1], "1")

    def test_clean_proof_over_cap_removes_temporary_workspace(self) -> None:
        temporary_proof_roots: list[Path] = []
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            temporary_proof_roots.append(proof_work)
            if "ctfwrap" in command:
                with (proof_work / "sparse-bomb").open("wb") as handle:
                    handle.truncate(128 * 1024)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(payload),
                    "",
                )
            return subprocess.CompletedProcess(command, 0, "", "")

        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(work_tree_max_bytes=64 * 1024),
            runner=fake_runner,
        )
        with self.assertRaisesRegex(
            SandboxError,
            "after clean proof command.*accounted byte limit",
        ):
            backend.run_clean_proof(CommandSpec(("true",)))

        self.assertTrue(temporary_proof_roots)
        self.assertTrue(
            all(not path.exists() for path in temporary_proof_roots)
        )

    def test_clean_proof_rejects_oversized_candidate_sidecar_and_cleans(
        self,
    ) -> None:
        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            run_id = "run-00000001"
            run_root = proof_work / ".ctf" / "runs" / run_id
            run_root.mkdir(parents=True)
            (run_root / "stdout.log").write_bytes(b"")
            (run_root / "stderr.log").write_bytes(b"")
            (run_root / FLAG_CANDIDATE_SIDECAR).write_bytes(
                b"x" * (1024 * 1024 + 1)
            )
            value = {
                "schema_version": 1,
                "kind": "run_result",
                "run_id": run_id,
                "status": "completed",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 1,
                "stdout_summary": "",
                "stderr_summary": "",
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_path": f"/work/.ctf/runs/{run_id}/stdout.log",
                "stderr_path": f"/work/.ctf/runs/{run_id}/stderr.log",
            }
            (run_root / "result.json").write_text(
                json.dumps(value),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(value),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with self.assertRaisesRegex(
            SandboxError,
            "flag candidate sidecar",
        ):
            backend.run_clean_proof(CommandSpec(("true",)))

        self.assertEqual(
            list((self.scope_a.work_dir / "proof").glob("clean-*")),
            [],
        )
        live_root = (
            self.scope_a.work_dir.parent / PROOF_LIVE_DIRECTORY
        )
        self.assertEqual(list(live_root.glob("clean-*")), [])

    def test_clean_proof_over_cap_removes_exact_durable_evidence(self) -> None:
        (self.work_a / "existing.bin").write_bytes(b"x" * (180 * 1024))
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 40 * 1024,
            "stderr_bytes": 40 * 1024,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            run_root = proof_work / ".ctf" / "runs" / "run-00000001"
            run_root.mkdir(parents=True)
            (run_root / "stdout.log").write_bytes(b"o" * (40 * 1024))
            (run_root / "stderr.log").write_bytes(b"e" * (40 * 1024))
            (run_root / "result.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        maximum_bytes = 256 * 1024
        backend = DockerSandboxBackend(
            self.scope_a,
            limits=DockerLimits(work_tree_max_bytes=maximum_bytes),
            runner=fake_runner,
        )
        with self.assertRaisesRegex(
            SandboxError,
            "after clean proof evidence persistence.*accounted byte limit",
        ):
            backend.run_clean_proof(CommandSpec(("true",)))

        proof_root = self.scope_a.work_dir / "proof"
        self.assertEqual(list(proof_root.glob("clean-*")), [])
        measure_work_tree(self.scope_a.work_dir, maximum_bytes=maximum_bytes)

    def test_clean_proof_interrupt_removes_exact_uncommitted_evidence(
        self,
    ) -> None:
        payload = {
            "schema_version": 1,
            "kind": "run_result",
            "run_id": "run-00000001",
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1,
            "stdout_summary": "",
            "stderr_summary": "",
            "stdout_bytes": 1,
            "stderr_bytes": 0,
            "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
            "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
        }

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            run_root = proof_work / ".ctf" / "runs" / "run-00000001"
            run_root.mkdir(parents=True)
            (run_root / "stdout.log").write_bytes(b"x")
            (run_root / "stderr.log").write_bytes(b"")
            (run_root / "result.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(payload),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        proof_root = self.scope_a.work_dir / "proof"
        real_mkdir = Path.mkdir
        mkdir_interrupt = KeyboardInterrupt(
            "synthetic proof directory creation interrupt"
        )
        mkdir_interrupted = False

        def interrupt_after_proof_mkdir(path, *args, **kwargs):
            nonlocal mkdir_interrupted
            result = real_mkdir(path, *args, **kwargs)
            if (
                not mkdir_interrupted
                and path.name.startswith("clean-")
            ):
                mkdir_interrupted = True
                raise mkdir_interrupt
            return result

        with (
            patch.object(
                Path,
                "mkdir",
                new=interrupt_after_proof_mkdir,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            backend.run_clean_proof(CommandSpec(("true",)))
        self.assertIs(raised.exception, mkdir_interrupt)
        self.assertEqual(list(proof_root.glob("clean-*")), [])

        real_stat = Path.stat
        stat_interrupt = KeyboardInterrupt(
            "synthetic proof directory identity interrupt"
        )
        stat_interrupted = False

        def interrupt_after_proof_stat(path, *args, **kwargs):
            nonlocal stat_interrupted
            result = real_stat(path, *args, **kwargs)
            if (
                not stat_interrupted
                and path.name.startswith("clean-")
                and kwargs.get("follow_symlinks") is False
            ):
                stat_interrupted = True
                raise stat_interrupt
            return result

        with (
            patch.object(
                Path,
                "stat",
                new=interrupt_after_proof_stat,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            backend.run_clean_proof(CommandSpec(("true",)))
        self.assertIs(raised.exception, stat_interrupt)
        self.assertEqual(list(proof_root.glob("clean-*")), [])

        for interruption in (
            KeyboardInterrupt("synthetic proof persistence interrupt"),
            SystemExit(23),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                patch(
                    "ctf_os.sandbox.docker.copy_bounded_regular",
                    side_effect=interruption,
                ),
                self.assertRaises(type(interruption)) as raised,
            ):
                backend.run_clean_proof(CommandSpec(("true",)))
            self.assertIs(raised.exception, interruption)
            self.assertEqual(list(proof_root.glob("clean-*")), [])
            self.assertEqual(
                list(
                    (
                        self.scope_a.work_dir.parent
                        / PROOF_LIVE_DIRECTORY
                    ).glob("clean-*")
                ),
                [],
            )

    def test_clean_proof_copies_only_manifest_verified_snapshot_bytes(
        self,
    ) -> None:
        source = self.work_a / "staging" / "snapshot.bin"
        source.parent.mkdir(parents=True)
        payload = b"immutable proof input"
        source.write_bytes(payload)
        proof_input = ProofInput(
            source_locator="staging/snapshot.bin",
            destination_locator="inputs/data.bin",
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        observed: list[bytes] = []

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            observed.append((proof_work / "inputs" / "data.bin").read_bytes())
            run_id = "run-00000001"
            run_root = proof_work / ".ctf" / "runs" / run_id
            run_root.mkdir(parents=True)
            for filename in ("stdout.log", "stderr.log"):
                (run_root / filename).write_bytes(b"")
            value = {
                "schema_version": 1,
                "kind": "run_result",
                "run_id": run_id,
                "status": "completed",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 1,
                "stdout_summary": "",
                "stderr_summary": "",
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_path": f"/work/.ctf/runs/{run_id}/stdout.log",
                "stderr_path": f"/work/.ctf/runs/{run_id}/stderr.log",
            }
            (run_root / "result.json").write_text(
                json.dumps(value),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(value),
                "",
            )

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        backend.run_clean_proof(
            CommandSpec(("true",)),
            proof_inputs=(proof_input,),
        )
        self.assertEqual(observed, [payload])

        source.write_bytes(b"mutated")
        with self.assertRaisesRegex(ScopeError, "immutable manifest"):
            backend.run_clean_proof(
                CommandSpec(("true",)),
                proof_inputs=(proof_input,),
            )

    def test_clean_proof_rejects_intermediate_destination_symlink(
        self,
    ) -> None:
        source = self.work_a / "staging" / "snapshot.bin"
        source.parent.mkdir(parents=True)
        payload = b"immutable proof input"
        source.write_bytes(payload)
        proof_input = ProofInput(
            source_locator="staging/snapshot.bin",
            destination_locator="inputs/nested/data.bin",
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        outside = self.root / "outside-inputs"
        outside.mkdir()

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            proof_work = Path(
                next(
                    component.removeprefix("src=")
                    for component in work_mount.split(",")
                    if component.startswith("src=")
                )
            )
            (proof_work / "inputs").symlink_to(
                outside,
                target_is_directory=True,
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with self.assertRaisesRegex(ScopeError, "unsafe directory"):
            backend.run_clean_proof(
                CommandSpec(("true",)),
                proof_inputs=(proof_input,),
            )
        self.assertFalse((outside / "nested" / "data.bin").exists())

    def test_bounded_copy_never_replaces_existing_snapshot(self) -> None:
        source_root = self.root / "bounded-source"
        source_root.mkdir()
        (source_root / "source.bin").write_bytes(b"replacement")
        destination = self.root / "snapshots" / "immutable.bin"
        destination.parent.mkdir()
        destination.write_bytes(b"trusted")

        with self.assertRaisesRegex(SafeFileError, "already exists"):
            copy_bounded_regular(
                source_root,
                "source.bin",
                destination,
            )

        self.assertEqual(destination.read_bytes(), b"trusted")
        self.assertEqual(
            list(destination.parent.glob(".*.tmp")),
            [],
        )

    def test_bounded_copy_removes_partial_file_when_size_limit_is_hit(
        self,
    ) -> None:
        source_root = self.root / "oversized-source"
        source_root.mkdir()
        (source_root / "source.bin").write_bytes(b"oversized")
        destination = self.root / "snapshots" / "bounded.bin"

        with self.assertRaisesRegex(SafeFileError, "size limit"):
            copy_bounded_regular(
                source_root,
                "source.bin",
                destination,
                maximum_bytes=4,
            )

        self.assertFalse(destination.exists())
        self.assertEqual(
            list(destination.parent.glob(".*.tmp")),
            [],
        )

    def test_bounded_copy_zero_write_fails_cleanly_and_recovers(
        self,
    ) -> None:
        for existing_destination in (False, True):
            with self.subTest(existing_destination=existing_destination):
                source_root = self.root / (
                    "zero-write-source-"
                    f"{int(existing_destination)}"
                )
                source_root.mkdir()
                payload = b"snapshot payload"
                (source_root / "source.bin").write_bytes(payload)
                destination = self.root / "snapshots" / (
                    f"zero-write-{int(existing_destination)}.bin"
                )
                destination.parent.mkdir(exist_ok=True)
                if existing_destination:
                    destination.write_bytes(b"trusted")

                with (
                    patch.object(
                        sandbox_files.os,
                        "write",
                        return_value=0,
                    ) as mocked_write,
                    self.assertRaisesRegex(
                        SafeFileError,
                        "made no progress",
                    ),
                ):
                    copy_bounded_regular(
                        source_root,
                        "source.bin",
                        destination,
                    )

                self.assertEqual(mocked_write.call_count, 1)
                if existing_destination:
                    self.assertEqual(
                        destination.read_bytes(),
                        b"trusted",
                    )
                    destination.unlink()
                else:
                    self.assertFalse(destination.exists())
                self.assertEqual(
                    list(destination.parent.glob(".*.tmp")),
                    [],
                )

                copy_bounded_regular(
                    source_root,
                    "source.bin",
                    destination,
                )
                self.assertEqual(destination.read_bytes(), payload)

    def test_bounded_copy_destination_open_failure_closes_source(
        self,
    ) -> None:
        source_root = self.root / "destination-open-source"
        source_root.mkdir()
        source = source_root / "source.bin"
        source.write_bytes(b"snapshot")
        destination = self.root / "destination-open" / "copy.bin"
        real_open = sandbox_files.os.open
        destination_open_calls = 0
        source_descriptor: int | None = None

        def fail_second_destination_open(path, flags, *args, **kwargs):
            nonlocal destination_open_calls, source_descriptor
            if (
                Path(path) == destination.parent
                and kwargs.get("dir_fd") is None
            ):
                destination_open_calls += 1
                if destination_open_calls == 2:
                    raise OSError(
                        "synthetic destination directory open failure"
                    )
            descriptor = real_open(path, flags, *args, **kwargs)
            if (
                str(path) == source.name
                and kwargs.get("dir_fd") is not None
                and not flags & os.O_DIRECTORY
            ):
                source_descriptor = descriptor
            return descriptor

        with (
            patch.object(
                sandbox_files.os,
                "open",
                side_effect=fail_second_destination_open,
            ),
            self.assertRaisesRegex(
                SafeFileError,
                "snapshot copy failed",
            ),
        ):
            copy_bounded_regular(
                source_root,
                source.name,
                destination,
            )

        self.assertEqual(destination_open_calls, 2)
        assert source_descriptor is not None
        with self.assertRaises(OSError) as closed:
            os.fstat(source_descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

    def test_bounded_copy_cleanup_continues_without_reclosing_peer(
        self,
    ) -> None:
        source_root = self.root / "cleanup-source"
        source_root.mkdir()
        source = source_root / "source.bin"
        source.write_bytes(b"snapshot")
        destination = self.root / "cleanup-destination" / "copy.bin"
        real_open = sandbox_files.os.open
        real_close = sandbox_files.os.close
        destination_open_calls = 0
        source_descriptor: int | None = None
        temporary_descriptor: int | None = None
        destination_descriptor: int | None = None
        peer_descriptor: int | None = None
        source_identity: tuple[int, int] | None = None
        source_close_calls = 0
        cleanup_interruption = KeyboardInterrupt(
            "synthetic ambiguous source close interruption"
        )

        def traced_open(path, flags, *args, **kwargs):
            nonlocal destination_descriptor
            nonlocal destination_open_calls
            nonlocal source_descriptor
            nonlocal source_identity
            nonlocal temporary_descriptor
            descriptor = real_open(path, flags, *args, **kwargs)
            if (
                Path(path) == destination.parent
                and kwargs.get("dir_fd") is None
            ):
                destination_open_calls += 1
                if destination_open_calls == 2:
                    destination_descriptor = descriptor
            elif (
                str(path) == source.name
                and kwargs.get("dir_fd") is not None
                and not flags & os.O_DIRECTORY
            ):
                source_descriptor = descriptor
                metadata = os.fstat(descriptor)
                source_identity = (metadata.st_dev, metadata.st_ino)
            elif str(path).endswith(".tmp"):
                temporary_descriptor = descriptor
            return descriptor

        def close_source_then_reopen_peer(descriptor: int) -> None:
            nonlocal peer_descriptor, source_close_calls
            if descriptor == source_descriptor:
                source_close_calls += 1
                if peer_descriptor is None:
                    real_close(descriptor)
                    replacement = real_open(
                        source,
                        os.O_RDONLY | os.O_CLOEXEC,
                    )
                    if replacement != descriptor:
                        os.dup2(
                            replacement,
                            descriptor,
                            inheritable=False,
                        )
                        real_close(replacement)
                    peer_descriptor = descriptor
                    raise cleanup_interruption
            real_close(descriptor)

        try:
            with (
                patch.object(
                    sandbox_files.os,
                    "open",
                    side_effect=traced_open,
                ),
                patch.object(
                    sandbox_files.os,
                    "close",
                    side_effect=close_source_then_reopen_peer,
                ),
                patch.object(
                    sandbox_files.os,
                    "write",
                    return_value=0,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                copy_bounded_regular(
                    source_root,
                    source.name,
                    destination,
                )

            assert source_descriptor is not None
            assert source_identity is not None
            assert peer_descriptor is not None
            assert temporary_descriptor is not None
            assert destination_descriptor is not None
            self.assertIs(raised.exception, cleanup_interruption)
            self.assertEqual(source_close_calls, 1)
            peer = os.fstat(peer_descriptor)
            self.assertEqual(
                (peer.st_dev, peer.st_ino),
                source_identity,
            )
            for descriptor in (
                temporary_descriptor,
                destination_descriptor,
            ):
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertEqual(
                list(destination.parent.glob(".*.tmp")),
                [],
            )
            self.assertTrue(
                any(
                    "cleanup interrupted while handling SafeFileError" in note
                    and "made no progress" in note
                    for note in getattr(raised.exception, "__notes__", ())
                )
            )
        finally:
            if peer_descriptor is not None:
                real_close(peer_descriptor)

    def test_track_descriptor_fstat_failure_closes_unpublished_fd(
        self,
    ) -> None:
        root = self.root / "failed-descriptor-handoff"
        root.mkdir()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        real_fstat = sandbox_files.os.fstat

        for error in (
            OSError("synthetic descriptor identity failure"),
            KeyboardInterrupt("synthetic descriptor identity interruption"),
            SystemExit("synthetic descriptor identity exit"),
        ):
            with self.subTest(error=type(error).__name__):
                descriptor = os.open(root, flags)
                owned: dict[int, tuple[int, int, int, int]] = {}

                def fail_target_fstat(value: int):
                    if value == descriptor:
                        raise error
                    return real_fstat(value)

                with (
                    patch.object(
                        sandbox_files.os,
                        "fstat",
                        side_effect=fail_target_fstat,
                    ),
                    self.assertRaises(type(error)) as raised,
                ):
                    sandbox_files._track_descriptor(
                        owned,
                        descriptor,
                    )

                self.assertIs(raised.exception, error)
                self.assertEqual(owned, {})
                with self.assertRaises(OSError) as closed:
                    real_fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_owned_descriptor_cleanup_never_recloses_same_inode_peer(
        self,
    ) -> None:
        root = self.root / "same-inode-owned-descriptor"
        root.mkdir()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        real_close = os.close

        for interruption in (
            KeyboardInterrupt("synthetic owned descriptor close interrupt"),
            SystemExit("synthetic owned descriptor close exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                owned: dict[int, tuple[int, int, int, int]] = {}
                descriptor = sandbox_files._track_descriptor(
                    owned,
                    os.open(root, flags),
                )
                opened = os.fstat(descriptor)
                identity = (opened.st_dev, opened.st_ino)
                close_calls: list[int] = []
                peer_descriptor: int | None = None

                def close_then_reopen_same_inode(value: int) -> None:
                    nonlocal peer_descriptor
                    close_calls.append(value)
                    if peer_descriptor is None:
                        real_close(value)
                        replacement = os.open(root, flags)
                        if replacement != value:
                            os.dup2(
                                replacement,
                                value,
                                inheritable=False,
                            )
                            real_close(replacement)
                        peer_descriptor = value
                        reopened = os.fstat(value)
                        self.assertEqual(
                            (reopened.st_dev, reopened.st_ino),
                            identity,
                        )
                        raise interruption
                    real_close(value)

                try:
                    with (
                        patch.object(
                            sandbox_files.os,
                            "close",
                            side_effect=close_then_reopen_same_inode,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        try:
                            sandbox_files._close_owned_descriptor(
                                owned,
                                descriptor,
                            )
                        finally:
                            sandbox_files._close_owned_descriptors(owned)

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(owned, {})
                    self.assertEqual(peer_descriptor, descriptor)
                    self.assertEqual(close_calls, [descriptor])
                    peer = os.fstat(descriptor)
                    self.assertEqual(
                        (peer.st_dev, peer.st_ino),
                        identity,
                    )
                finally:
                    try:
                        real_close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

    def test_owned_descriptor_cleanup_prioritizes_control_interruption(
        self,
    ) -> None:
        root = self.root / "descriptor-cleanup-priority"
        root.mkdir()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        real_close = sandbox_files.os.close
        owned: dict[int, tuple[int, int, int, int]] = {}
        first = sandbox_files._track_descriptor(
            owned,
            os.open(root, flags),
        )
        second = sandbox_files._track_descriptor(
            owned,
            os.open(root, flags),
        )
        ordinary_error = OSError("synthetic first close error")
        interruption = KeyboardInterrupt(
            "synthetic later close interruption"
        )
        close_calls: list[int] = []

        def fail_both_closes(descriptor: int) -> None:
            close_calls.append(descriptor)
            real_close(descriptor)
            if descriptor == first:
                raise ordinary_error
            if descriptor == second:
                raise interruption

        with (
            patch.object(
                sandbox_files.os,
                "close",
                side_effect=fail_both_closes,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            sandbox_files._close_owned_descriptors(owned)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(close_calls, [first, second])
        self.assertEqual(owned, {})
        self.assertTrue(
            any(
                str(ordinary_error) in note
                for note in getattr(raised.exception, "__notes__", ())
            )
        )
        for descriptor in (first, second):
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_descriptor_handoffs_never_reclose_concurrently_reused_fd(
        self,
    ) -> None:
        helper_lines, helper_start = inspect.getsourcelines(
            sandbox_files._close_owned_descriptor
        )
        close_completed_line = helper_start + next(
            index
            for index, line in enumerate(helper_lines)
            if line.strip() == "return None"
        )
        helper_code = sandbox_files._close_owned_descriptor.__code__
        foreign_path = self.root / "foreign-descriptor.txt"
        foreign_path.write_bytes(b"foreign")

        def run_case(
            *,
            operation,
            recovery,
            caller_code,
            interruption: BaseException,
        ) -> None:
            foreign_source = os.open(
                foreign_path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
            descriptor_ready = threading.Event()
            descriptor_reused = threading.Event()
            target: list[int] = []
            thread_errors: list[BaseException] = []

            def reuse_closed_number() -> None:
                if not descriptor_ready.wait(2):
                    thread_errors.append(
                        RuntimeError("descriptor reuse was not requested")
                    )
                    descriptor_reused.set()
                    return
                try:
                    os.dup2(
                        foreign_source,
                        target[0],
                        inheritable=False,
                    )
                except BaseException as error:
                    thread_errors.append(error)
                finally:
                    descriptor_reused.set()

            reuse_thread = threading.Thread(
                target=reuse_closed_number,
                daemon=True,
            )
            reuse_thread.start()
            triggered = False

            def interrupt_after_close(frame, event, _argument):
                nonlocal triggered
                if (
                    not triggered
                    and event == "line"
                    and frame.f_code is helper_code
                    and frame.f_lineno == close_completed_line
                    and frame.f_back is not None
                    and frame.f_back.f_code is caller_code
                ):
                    triggered = True
                    sys.settrace(None)
                    target.append(frame.f_locals["descriptor"])
                    descriptor_ready.set()
                    if not descriptor_reused.wait(2):
                        raise RuntimeError(
                            "concurrent descriptor reuse timed out"
                        )
                    if thread_errors:
                        raise thread_errors[0]
                    raise interruption
                return interrupt_after_close

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_after_close)
                with self.assertRaises(
                    type(interruption)
                ) as raised:
                    operation()
            finally:
                sys.settrace(previous_trace)
                descriptor_ready.set()
                reuse_thread.join(2)

            self.assertIs(raised.exception, interruption)
            self.assertTrue(triggered)
            self.assertFalse(reuse_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertEqual(len(target), 1)
            reused_descriptor = target[0]
            try:
                self.assertEqual(
                    os.fstat(reused_descriptor).st_ino,
                    os.fstat(foreign_source).st_ino,
                )
                self.assertEqual(os.read(reused_descriptor, 7), b"foreign")
                recovery()
                os.fstat(reused_descriptor)
            finally:
                for descriptor in {
                    reused_descriptor,
                    foreign_source,
                }:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

        for exception_type in (KeyboardInterrupt, SystemExit):
            exception_name = exception_type.__name__.lower()
            with self.subTest(
                operation="relative-directory",
                interruption=exception_type.__name__,
            ):
                root = self.root / f"handoff-directory-{exception_name}"
                root.mkdir()

                def ensure_operation() -> None:
                    sandbox_files.ensure_relative_directory(
                        root,
                        "one/two",
                    )

                def ensure_recovery() -> None:
                    result = sandbox_files.ensure_relative_directory(
                        root,
                        "one/two",
                    )
                    self.assertTrue(result.is_dir())

                run_case(
                    operation=ensure_operation,
                    recovery=ensure_recovery,
                    caller_code=(
                        sandbox_files.ensure_relative_directory.__code__
                    ),
                    interruption=exception_type(
                        "synthetic directory handoff interrupt"
                    ),
                )

            with self.subTest(
                operation="relative-file",
                interruption=exception_type.__name__,
            ):
                root = self.root / f"handoff-file-{exception_name}"
                nested = root / "one" / "two"
                nested.mkdir(parents=True)
                (nested / "source.bin").write_bytes(b"payload")

                def open_operation() -> None:
                    descriptor, _metadata, _locator = (
                        sandbox_files._open_relative_regular(
                            root,
                            "one/two/source.bin",
                            maximum_bytes=1024,
                        )
                    )
                    os.close(descriptor)

                def open_recovery() -> None:
                    descriptor, _metadata, locator = (
                        sandbox_files._open_relative_regular(
                            root,
                            "one/two/source.bin",
                            maximum_bytes=1024,
                        )
                    )
                    try:
                        self.assertEqual(os.read(descriptor, 7), b"payload")
                        self.assertEqual(locator, "one/two/source.bin")
                    finally:
                        os.close(descriptor)

                run_case(
                    operation=open_operation,
                    recovery=open_recovery,
                    caller_code=(
                        sandbox_files._open_relative_regular.__code__
                    ),
                    interruption=exception_type(
                        "synthetic file handoff interrupt"
                    ),
                )

            with self.subTest(
                operation="temporary-copy",
                interruption=exception_type.__name__,
            ):
                root = self.root / f"handoff-copy-{exception_name}"
                root.mkdir()
                (root / "source.bin").write_bytes(b"snapshot")
                destination = self.root / "snapshots" / (
                    f"handoff-{exception_name}.bin"
                )

                def copy_operation() -> None:
                    copy_bounded_regular(
                        root,
                        "source.bin",
                        destination,
                    )

                def copy_recovery() -> None:
                    copy_bounded_regular(
                        root,
                        "source.bin",
                        destination,
                    )
                    self.assertEqual(
                        destination.read_bytes(),
                        b"snapshot",
                    )

                run_case(
                    operation=copy_operation,
                    recovery=copy_recovery,
                    caller_code=copy_bounded_regular.__code__,
                    interruption=exception_type(
                        "synthetic temporary close interrupt"
                    ),
                )

    def test_bounded_copy_interrupt_after_link_removes_exact_temporary(
        self,
    ) -> None:
        source_root = self.root / "interrupt-source"
        source_root.mkdir()
        (source_root / "source.bin").write_bytes(b"snapshot")
        destination = self.root / "snapshots" / "interrupted.bin"
        real_unlink = sandbox_files.os.unlink
        interrupted = False
        interruption = KeyboardInterrupt("synthetic post-link interrupt")

        def interrupt_first_temporary_unlink(path, *args, **kwargs):
            nonlocal interrupted
            if not interrupted and str(path).endswith(".tmp"):
                interrupted = True
                raise interruption
            return real_unlink(path, *args, **kwargs)

        with (
            patch.object(
                sandbox_files.os,
                "unlink",
                side_effect=interrupt_first_temporary_unlink,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            copy_bounded_regular(
                source_root,
                "source.bin",
                destination,
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(destination.exists())
        self.assertEqual(
            list(destination.parent.glob(".*.tmp")),
            [],
        )

    def test_clean_proof_rejects_symlink_persistence_root(self) -> None:
        outside = self.root / "outside-proof"
        outside.mkdir()
        (self.scope_a.work_dir / "proof").symlink_to(outside)

        def fake_runner(command, **_kwargs):
            work_mount = next(
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--mount" and "dst=/work" in command[index + 1]
            )
            source_text = next(
                component.removeprefix("src=")
                for component in work_mount.split(",")
                if component.startswith("src=")
            )
            proof_work = Path(source_text)
            if "ctfwrap" not in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            run_root = proof_work / ".ctf" / "runs" / "run-00000001"
            run_root.mkdir(parents=True)
            value = {
                "schema_version": 1,
                "kind": "run_result",
                "run_id": "run-00000001",
                "status": "completed",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 1,
                "stdout_summary": "",
                "stderr_summary": "",
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
                "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
            }
            for filename in ("stdout.log", "stderr.log"):
                (run_root / filename).write_bytes(b"")
            (run_root / "result.json").write_text(
                json.dumps(value),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

        backend = DockerSandboxBackend(self.scope_a, runner=fake_runner)
        with self.assertRaisesRegex(ScopeError, "must not be a symlink"):
            backend.run_clean_proof(CommandSpec(("true",)))
        self.assertEqual(list(outside.iterdir()), [])

    def test_capability_cannot_address_another_challenge(self) -> None:
        service = SandboxService(CapabilityAuthority(b"x" * 32))
        client_a = _FakeClient(self.scope_a.fingerprint)
        client_b = _FakeClient(self.scope_b.fingerprint)
        service.register(client_a)
        service.register(client_b)
        token_a = service.issue(self.scope_a.fingerprint)

        good = service.handle_bytes(
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "token": token_a,
                        "operation": "run",
                        "params": {
                            "command": {
                                "argv": ["true"],
                                "timeout_seconds": 1,
                                "summary_bytes": 1,
                                "environment": {},
                                "network_target": None,
                            }
                        },
                    }
                )
                + "\n"
            ).encode()
        )
        self.assertTrue(json.loads(good)["ok"])

        cross_scope = service.handle_bytes(
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "token": token_a,
                        "operation": "job_status",
                        "params": {
                            "ref": asdict(
                                JobRef(
                                    "job-00000001",
                                    self.scope_b.fingerprint,
                                )
                            )
                        },
                    }
                )
                + "\n"
            ).encode()
        )
        response = json.loads(cross_scope)
        self.assertFalse(response["ok"])
        self.assertIn("another challenge", response["error"]["message"])

        background = service.handle_bytes(
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "token": token_a,
                        "operation": "start_job",
                        "params": {
                            "command": {
                                "argv": ["sleep", "60"],
                            }
                        },
                    }
                )
                + "\n"
            ).encode()
        )
        response = json.loads(background)
        self.assertFalse(response["ok"])
        self.assertIn("lease supervisor", response["error"]["message"])

    def test_invalid_capability_is_rejected_before_backend(self) -> None:
        service = SandboxService(CapabilityAuthority(b"x" * 32))
        service.register(_FakeClient(self.scope_a.fingerprint))
        response = json.loads(
            service.handle_bytes(
                json.dumps(
                    {
                        "schema_version": 1,
                        "token": "not-a-token",
                        "operation": "run",
                        "params": {},
                    }
                ).encode()
            )
        )
        self.assertFalse(response["ok"])

    def test_unix_client_round_trip_uses_capability_scope(self) -> None:
        service = SandboxService(CapabilityAuthority(b"x" * 32))
        service.register(_FakeClient(self.scope_a.fingerprint))
        token = service.issue(self.scope_a.fingerprint)
        socket_path = self.root / "runtime" / "ctfosd.sock"
        server = UnixSandboxServer(socket_path, service)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            client = UnixChallengeSandboxClient(
                socket_path,
                token,
                self.scope_a.fingerprint,
            )
            result = client.run(CommandSpec(("true",), timeout_seconds=1))
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout_summary, "ok")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(socket_path.exists())

    def test_unix_client_keeps_rpc_open_through_cleanup_grace(self) -> None:
        started = threading.Event()
        finished = threading.Event()

        class CleanupClient(_FakeClient):
            def run(inner_self, spec):
                started.set()
                time.sleep(0.2)
                finished.set()
                return super().run(spec)

        service = SandboxService(CapabilityAuthority(b"x" * 32))
        service.register(CleanupClient(self.scope_a.fingerprint))
        token = service.issue(self.scope_a.fingerprint)
        socket_path = self.root / "runtime-grace" / "ctfosd.sock"
        server = UnixSandboxServer(socket_path, service)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            client = UnixChallengeSandboxClient(
                socket_path,
                token,
                self.scope_a.fingerprint,
            )
            result = client.run(
                CommandSpec(
                    ("true",),
                    timeout_seconds=1,
                    deadline_monotonic_seconds=time.monotonic() + 0.05,
                )
            )
            self.assertTrue(started.is_set())
            self.assertTrue(
                finished.is_set(),
                "client returned before bounded daemon cleanup completed",
            )
            self.assertEqual(result.exit_code, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_unix_rpc_deadline_is_total_across_partial_receives(self) -> None:
        socket_path = self.root / "partial.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        server_finished = threading.Event()

        def trickle_response() -> None:
            try:
                connection, _address = listener.accept()
                with connection:
                    request = bytearray()
                    while b"\n" not in request:
                        block = connection.recv(4096)
                        if not block:
                            break
                        request.extend(block)
                    response = (
                        json.dumps(
                            {
                                "schema_version": 1,
                                "ok": True,
                                "result": {},
                            }
                        )
                        + "\n"
                    ).encode()
                    for byte in response:
                        try:
                            connection.sendall(bytes((byte,)))
                        except (BrokenPipeError, ConnectionResetError):
                            break
                        time.sleep(0.04)
            finally:
                listener.close()
                server_finished.set()

        thread = threading.Thread(target=trickle_response)
        thread.start()
        client = UnixChallengeSandboxClient(
            socket_path,
            "token",
            self.scope_a.fingerprint,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(SandboxError, "deadline|timed out"):
            client._call(
                "synthetic",
                {},
                rpc_deadline_monotonic=time.monotonic() + 0.15,
            )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.5)
        thread.join(timeout=2)
        self.assertTrue(server_finished.is_set())
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
