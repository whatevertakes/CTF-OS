#!/usr/bin/env python3
"""Hostile tests for the multi-format Rev runtime executor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[2]
REV_TEMPLATES = REPOSITORY / "ctf-os-image" / "templates" / "rev"
sys.path.insert(0, str(REV_TEMPLATES))
sys.path.insert(0, str(REPOSITORY))

from ctf_os.contracts.rev_runtime_v1 import (  # noqa: E402
    build_rev_runtime_v1_spec,
)

module_spec = importlib.util.spec_from_file_location(
    "ctf_rev_runtime_exec_under_test",
    REV_TEMPLATES / "runtime_exec.py",
)
assert module_spec is not None and module_spec.loader is not None
runtime_exec = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = runtime_exec
module_spec.loader.exec_module(runtime_exec)


def _binding(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


class RevRuntimeExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctf-rev-runtime-exec-"
        )
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.work = self.root / "work"
        self.challenge.mkdir()
        self.work.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _compile(self, relative: str, source_text: str) -> Path:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("cc is unavailable")
        source = self.root / "source.c"
        source.write_text(source_text, encoding="utf-8")
        destination = self.challenge / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            (compiler, str(source), "-o", str(destination)),
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        destination.chmod(0o500)
        return destination

    def _write_spec(self, spec) -> None:
        (self.work / "runtime.json").write_bytes(spec.canonical_bytes)

    def _invoke(self) -> subprocess.CompletedProcess[bytes]:
        helper = (
            "import pathlib,sys,runtime_exec;"
            "raise SystemExit(runtime_exec.stdin_exec._preserve_target_status("
            "runtime_exec.execute_runtime("
            "'/work/runtime.json','/work/input.bin',"
            "challenge_root=pathlib.Path(sys.argv[1]),"
            "work_root=pathlib.Path(sys.argv[2]))))"
        )
        return subprocess.run(
            (
                sys.executable,
                "-c",
                helper,
                str(self.challenge),
                str(self.work),
            ),
            capture_output=True,
            env={
                "PYTHONPATH": str(REV_TEMPLATES),
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            },
            check=False,
        )

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_real_native_three_positive_three_negative_execution(self) -> None:
        target = self._compile(
            "bin/oracle",
            r"""
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char input[32] = {0};
    size_t count;
    if (argc != 3 || strcmp(argv[1], "--mode") != 0 ||
        strcmp(argv[2], "proof") != 0) {
        return 41;
    }
    count = fread(input, 1, sizeof(input), stdin);
    if (count == 7 && memcmp(input, "secret\n", 7) == 0) {
        fputs("flag{runtime-exec-positive}\n", stdout);
        return 0;
    }
    fputs("rejected\n", stdout);
    return 7;
}
""",
        )
        dependency_payload = b"exact-sidecar-binding"
        dependency = self.challenge / "data" / "sidecar.bin"
        dependency.parent.mkdir()
        dependency.write_bytes(dependency_payload)
        dependency.chmod(0o400)
        target_payload = target.read_bytes()
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding("bin/oracle", target_payload),
            dependencies=(
                _binding("data/sidecar.bin", dependency_payload),
            ),
            argv=("--mode", "proof"),
            working_directory="bin",
        )
        self._write_spec(spec)
        accepted = b"secret\n"
        attempts = (
            accepted,
            accepted,
            accepted,
            bytes((accepted[0] ^ 1,)) + accepted[1:],
            accepted[:-1] + bytes((accepted[-1] ^ 0x80,)),
            accepted[:-1],
        )
        observed: list[tuple[int, bytes]] = []
        for payload in attempts:
            (self.work / "input.bin").write_bytes(payload)
            completed = self._invoke()
            observed.append((completed.returncode, completed.stdout))
        self.assertEqual(
            observed[:3],
            [(0, b"flag{runtime-exec-positive}\n")] * 3,
        )
        self.assertEqual(
            observed[3:],
            [(7, b"rejected\n")] * 3,
        )
        self.assertTrue(
            all(b"flag{" not in output for _status, output in observed[3:])
        )

    def test_contract_generated_specs_select_only_fixed_runtimes(self) -> None:
        source = _binding("bin/target", b"target")
        dependency = _binding("lib/helper.jar", b"helper")
        cases = (
            (
                {
                    "format": "elf",
                    "runtime": "qemu-user",
                    "architecture": "aarch64",
                },
                "/usr/bin/qemu-aarch64-static",
            ),
            ({"format": "pe", "runtime": "wine"}, "/usr/local/bin/wine"),
            (
                {"format": "java-jar", "runtime": "java"},
                "/usr/bin/java",
            ),
            (
                {
                    "format": "java-class",
                    "runtime": "java",
                    "main_class": "ctf.Main",
                },
                "/usr/bin/java",
            ),
            (
                {"format": "dotnet", "runtime": "dotnet"},
                "/usr/bin/dotnet",
            ),
            (
                {"format": "dotnet", "runtime": "mono"},
                "/usr/bin/mono",
            ),
            (
                {
                    "format": "wasm",
                    "runtime": "node-wasi",
                    "wasm_entrypoint": "_start",
                },
                "/usr/bin/node",
            ),
        )
        for values, expected in cases:
            with self.subTest(values=values):
                selected = dict(values)
                if selected["format"] == "java-class":
                    selected_source = _binding(
                        "ctf/Main.class",
                        b"\xca\xfe\xba\xbeclass",
                    )
                elif selected["format"] == "wasm":
                    selected_source = _binding(
                        "target.wasm",
                        b"\x00asm\x01\x00\x00\x00",
                    )
                else:
                    selected_source = source
                spec = build_rev_runtime_v1_spec(
                    source=selected_source,
                    dependencies=(dependency,),
                    argv=("--explicit", "value"),
                    **selected,
                )
                parsed = runtime_exec._parse_spec(spec.canonical_bytes)
                command, executable, environment = (
                    runtime_exec._runtime_invocation(parsed)
                )
                self.assertEqual(command[0], expected)
                self.assertIs(executable, None)
                self.assertIs(command, tuple(command))
                self.assertNotIn("candidate", repr(command).casefold())
                self.assertNotIn("LD_PRELOAD", environment)
                self.assertEqual(environment["HOME"], "/nonexistent")

    def test_dex_and_apk_are_rejected_before_spawn(self) -> None:
        for binary_format, payload in (
            ("dex", b"dex\n035\x00" + b"\x00" * 64),
            ("apk", b"PK\x03\x04" + b"\x00" * 64),
        ):
            with self.subTest(binary_format=binary_format):
                source = self.challenge / f"app.{binary_format}"
                source.write_bytes(payload)
                spec = build_rev_runtime_v1_spec(
                    format=binary_format,
                    runtime="unsupported",
                    source=_binding(source.name, payload),
                )
                self._write_spec(spec)
                (self.work / "input.bin").write_bytes(b"input")
                with (
                    mock.patch.object(
                        runtime_exec.subprocess,
                        "run",
                    ) as run,
                    self.assertRaisesRegex(
                        runtime_exec.RuntimeExecError,
                        "runtime_unsupported_dex_apk",
                    ),
                ):
                    runtime_exec.execute_runtime(
                        "/work/runtime.json",
                        "/work/input.bin",
                        challenge_root=self.challenge,
                        work_root=self.work,
                    )
                run.assert_not_called()

    def test_decompiler_text_cannot_be_confirmed_as_executable(self) -> None:
        payload = b"int main() { return strcmp(input, \"secret\"); }\n"
        source = self.challenge / "decompiler-output.c"
        source.write_bytes(payload)
        source.chmod(0o500)
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding(source.name, payload),
        )
        self._write_spec(spec)
        (self.work / "input.bin").write_bytes(b"secret")
        with (
            mock.patch.object(runtime_exec.subprocess, "run") as run,
            self.assertRaisesRegex(
                runtime_exec.RuntimeExecError,
                "runtime_source_format_mismatch",
            ),
        ):
            runtime_exec.execute_runtime(
                "/work/runtime.json",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        run.assert_not_called()

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_unbound_runtime_visible_sidecar_fails_closed(self) -> None:
        target = self._compile(
            "main",
            "int main(void) { return 0; }\n",
        )
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding("main", target.read_bytes()),
        )
        self._write_spec(spec)
        (self.work / "input.bin").write_bytes(b"")
        (self.challenge / "main.runtimeconfig.json").write_text(
            '{"unbound":true}\n',
            encoding="utf-8",
        )
        with (
            mock.patch.object(runtime_exec.subprocess, "run") as run,
            self.assertRaisesRegex(
                runtime_exec.RuntimeExecError,
                "runtime_unbound_challenge_path",
            ),
        ):
            runtime_exec.execute_runtime(
                "/work/runtime.json",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        run.assert_not_called()

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_source_or_dependency_tamper_and_symlink_fail_closed(self) -> None:
        target = self._compile(
            "main",
            "int main(void) { return 0; }\n",
        )
        dependency = self.challenge / "dep.bin"
        dependency.write_bytes(b"before")
        dependency.chmod(0o400)
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding("main", target.read_bytes()),
            dependencies=(_binding("dep.bin", b"before"),),
        )
        self._write_spec(spec)
        (self.work / "input.bin").write_bytes(b"")

        dependency.chmod(0o600)
        dependency.write_bytes(b"after!")
        dependency.chmod(0o400)
        with (
            mock.patch.object(runtime_exec.subprocess, "run") as run,
            self.assertRaisesRegex(
                runtime_exec.RuntimeExecError,
                "runtime_file_binding_mismatch",
            ),
        ):
            runtime_exec.execute_runtime(
                "/work/runtime.json",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        run.assert_not_called()

        dependency.unlink()
        dependency.symlink_to(target)
        with (
            mock.patch.object(runtime_exec.subprocess, "run") as run,
            self.assertRaises(Exception),
        ):
            runtime_exec.execute_runtime(
                "/work/runtime.json",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        run.assert_not_called()

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_guest_status_and_transport_failure_are_distinct(self) -> None:
        target = self._compile(
            "exit-23",
            "int main(void) { return 23; }\n",
        )
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding("exit-23", target.read_bytes()),
        )
        self._write_spec(spec)
        (self.work / "input.bin").write_bytes(b"")
        self.assertEqual(self._invoke().returncode, 23)

        with (
            mock.patch.object(
                runtime_exec.subprocess,
                "run",
                side_effect=OSError("spawn failed"),
            ),
            self.assertRaisesRegex(
                runtime_exec.RuntimeExecError,
                "runtime_spawn_failed",
            ) as raised,
        ):
            runtime_exec.execute_runtime(
                "/work/runtime.json",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        self.assertEqual(raised.exception.exit_code, 125)

    def test_noncanonical_unknown_or_candidate_bearing_spec_is_rejected(
        self,
    ) -> None:
        payload = b"\x7fELF" + b"\x00" * 64
        base = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_binding("main", payload),
        ).to_dict()
        mutations = []
        candidate = dict(base)
        candidate["candidate"] = "flag{must-not-be-an-oracle-input}"
        mutations.append(candidate)
        environment = dict(base)
        environment["environment"] = {"PATH": "/tmp"}
        mutations.append(environment)
        shell = dict(base)
        shell["shell"] = True
        mutations.append(shell)
        for index, value in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    runtime_exec.RuntimeExecError,
                    "runtime_spec_schema_invalid",
                ),
            ):
                runtime_exec._parse_spec(
                    (
                        json.dumps(
                            value,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("ascii")
                )


if __name__ == "__main__":
    unittest.main()
