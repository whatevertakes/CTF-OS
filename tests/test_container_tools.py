from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from csv import reader
from pathlib import Path

from ctf_os import container_tools


class ContainerToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_native_cdi_is_preferred(self) -> None:
        def fake_runner(command, **kwargs):
            self.assertEqual(command, ["/usr/bin/nvidia-ctk", "cdi", "list"])
            return subprocess.CompletedProcess(
                command, 0, "nvidia.com/gpu=all\n", ""
            )

        plan = container_tools.detect_gpu_plan(
            policy="required",
            runner=fake_runner,
            which=lambda name: "/usr/bin/nvidia-ctk",
        )

        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.mode, "cdi")
        self.assertIn("nvidia.com/gpu=all", plan.docker_flags)

    def test_required_gpu_fails_without_any_passthrough(self) -> None:
        with self.assertRaisesRegex(container_tools.CLIError, "GPU가 필요"):
            container_tools.detect_gpu_plan(
                policy="required",
                runner=lambda *args, **kwargs: subprocess.CompletedProcess(
                    args[0], 0, json.dumps({"runc": {}}), ""
                ),
                which=lambda name: None,
            )

    def test_run_argv_enables_ptrace_kvm_gpu_and_network(self) -> None:
        challenge = self.root / "challenge"
        work = self.root / "work"
        challenge.mkdir()
        work.mkdir()
        gpu = container_tools.GPUPlan(
            mode="test",
            detail="test GPU",
            docker_flags=("--device", "nvidia.com/gpu=all"),
        )
        config = container_tools.RunConfig(
            image="ctf-os:core",
            command=("qemu-system-x86_64", "--version"),
            network="bridge",
            challenge=challenge,
            work=work,
        )

        argv = container_tools.build_docker_run_argv(
            config, gpu_plan=gpu, kvm_available=True
        )

        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        self.assertIn("SYS_PTRACE", argv)
        self.assertIn("seccomp=unconfined", argv)
        self.assertIn("/dev/kvm", argv)
        self.assertIn("nvidia.com/gpu=all", argv)
        self.assertIn("bridge", argv)
        self.assertTrue(
            any(
                str(challenge) in argument and "readonly" in argument
                for argument in argv
            )
        )
        self.assertTrue(any(str(work) in argument for argument in argv))
        self.assertEqual(
            argv[-3:],
            ["ctf-os:core", "qemu-system-x86_64", "--version"],
        )

    def test_ptrace_can_be_explicitly_disabled(self) -> None:
        config = container_tools.RunConfig(
            image="ctf-os:core",
            command=("true",),
            ptrace=False,
            kvm_policy="off",
            gpu_policy="off",
        )

        argv = container_tools.build_docker_run_argv(
            config, gpu_plan=None, kvm_available=False
        )

        self.assertNotIn("SYS_PTRACE", argv)
        self.assertNotIn("seccomp=unconfined", argv)

    def test_mount_paths_with_commas_and_quotes_are_csv_encoded(self) -> None:
        challenge = self.root / 'challenge,with"quote'
        work = self.root / "work,with,commas"
        challenge.mkdir()
        work.mkdir()
        config = container_tools.RunConfig(
            image="ctf-os:core",
            command=("true",),
            challenge=challenge,
            work=work,
            kvm_policy="off",
            gpu_policy="off",
        )

        argv = container_tools.build_docker_run_argv(
            config,
            gpu_plan=None,
            kvm_available=False,
        )
        specifications = [
            argv[index + 1]
            for index, argument in enumerate(argv[:-1])
            if argument == "--mount"
        ]
        decoded = [next(reader([value])) for value in specifications]

        self.assertIn(f"src={challenge}", decoded[0])
        self.assertIn("dst=/challenge", decoded[0])
        self.assertIn("readonly", decoded[0])
        self.assertIn(f"src={work}", decoded[1])
        self.assertIn("dst=/work", decoded[1])

    def test_doctor_reports_detected_capabilities(self) -> None:
        gpu = container_tools.GPUPlan(
            mode="cdi",
            detail="verified",
            docker_flags=(),
        )
        output = io.StringIO()
        errors = io.StringIO()

        original_gpu = container_tools.detect_gpu_plan
        original_kvm = container_tools.detect_kvm
        container_tools.detect_gpu_plan = lambda **kwargs: gpu
        container_tools.detect_kvm = lambda **kwargs: True
        try:
            with redirect_stdout(output), redirect_stderr(errors):
                status = container_tools.main(["doctor"])
        finally:
            container_tools.detect_gpu_plan = original_gpu
            container_tools.detect_kvm = original_kvm

        self.assertEqual(status, 0)
        self.assertEqual(errors.getvalue(), "")
        result = json.loads(output.getvalue())
        self.assertEqual(result["gpu"]["mode"], "cdi")
        self.assertTrue(result["kvm"]["available"])
        self.assertTrue(result["ptrace"]["enabled_by_default"])


if __name__ == "__main__":
    unittest.main()
