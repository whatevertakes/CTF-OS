from __future__ import annotations

import copy
import hashlib
import json
import unittest

from ctf_os.contracts.rev_runtime_v1 import (
    REV_RUNTIME_V1_PROTOCOL,
    RevRuntimeV1Error,
    RevRuntimeV1Spec,
    build_rev_runtime_v1_spec,
)


def _file(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


class RevRuntimeV1ContractTests(unittest.TestCase):
    def test_all_supported_runtime_shapes_round_trip_canonically(self) -> None:
        source = _file("bin/challenge", b"source")
        dependency = _file("lib/helper.bin", b"helper")
        cases = (
            {
                "format": "elf",
                "runtime": "native",
                "argv": ("--mode", "proof"),
            },
            {
                "format": "elf",
                "runtime": "qemu-user",
                "architecture": "aarch64",
                "qemu_ld_prefix": "sysroot",
                "dependencies": (
                    _file("sysroot/lib/ld-linux.so", b"loader"),
                ),
            },
            {"format": "pe", "runtime": "wine"},
            {"format": "java-jar", "runtime": "java"},
            {
                "format": "java-class",
                "runtime": "java",
                "main_class": "ctf.Main",
            },
            {"format": "dotnet", "runtime": "dotnet"},
            {"format": "dotnet", "runtime": "mono"},
            {
                "format": "wasm",
                "runtime": "node-wasi",
                "wasm_entrypoint": "_start",
            },
        )
        for values in cases:
            with self.subTest(values=values):
                selected = dict(values)
                dependencies = selected.pop(
                    "dependencies",
                    (dependency,),
                )
                spec = build_rev_runtime_v1_spec(
                    source=source,
                    dependencies=dependencies,
                    working_directory=".",
                    **selected,
                )
                self.assertTrue(spec.supported)
                self.assertIsNone(spec.unsupported_reason)
                decoded = json.loads(spec.canonical_bytes)
                self.assertEqual(
                    RevRuntimeV1Spec.from_mapping(decoded),
                    spec,
                )
                self.assertEqual(
                    len(spec.sha256),
                    64,
                )
                self.assertNotIn("candidate", decoded)
                self.assertNotIn("expected_output", decoded)

    def test_dex_and_apk_are_explicitly_unsupported(self) -> None:
        for binary_format in ("dex", "apk"):
            with self.subTest(binary_format=binary_format):
                spec = build_rev_runtime_v1_spec(
                    format=binary_format,
                    runtime="unsupported",
                    source=_file(f"app.{binary_format}", b"mobile"),
                )
                self.assertFalse(spec.supported)
                self.assertEqual(
                    spec.unsupported_reason,
                    "runtime_unsupported_dex_apk",
                )
                with self.assertRaisesRegex(
                    RevRuntimeV1Error,
                    "runtime_unsupported_dex_apk",
                ):
                    spec.require_supported()

    def test_dependencies_are_exact_sorted_unique_bindings(self) -> None:
        base = build_rev_runtime_v1_spec(
            format="java-jar",
            runtime="java",
            source=_file("app/main.jar", b"main"),
            dependencies=(
                _file("lib/a.jar", b"a"),
                _file("lib/b.jar", b"b"),
            ),
            working_directory="app",
        ).to_dict()
        mutations = []
        reversed_dependencies = copy.deepcopy(base)
        reversed_dependencies["dependencies"].reverse()
        mutations.append(reversed_dependencies)
        duplicate = copy.deepcopy(base)
        duplicate["dependencies"][1]["path"] = "lib/a.jar"
        mutations.append(duplicate)
        source_reused = copy.deepcopy(base)
        source_reused["dependencies"][0]["path"] = "app/main.jar"
        mutations.append(source_reused)
        uppercase_hash = copy.deepcopy(base)
        uppercase_hash["dependencies"][0]["sha256"] = "A" * 64
        mutations.append(uppercase_hash)
        bool_size = copy.deepcopy(base)
        bool_size["dependencies"][0]["size_bytes"] = True
        mutations.append(bool_size)
        extra_key = copy.deepcopy(base)
        extra_key["dependencies"][0]["role"] = "classpath"
        mutations.append(extra_key)

        for index, value in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaises(RevRuntimeV1Error),
            ):
                RevRuntimeV1Spec.from_mapping(value)

    def test_shell_environment_and_path_injection_fail_closed(self) -> None:
        base = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_file("bin/main", b"main"),
        ).to_dict()
        mutations = []
        shell = copy.deepcopy(base)
        shell["shell"] = True
        mutations.append(shell)
        environment = copy.deepcopy(base)
        environment["environment"] = {"LD_PRELOAD": "/tmp/evil.so"}
        mutations.append(environment)
        candidate = copy.deepcopy(base)
        candidate["candidate"] = "flag{must-not-enter-runtime-spec}"
        mutations.append(candidate)
        traversal = copy.deepcopy(base)
        traversal["source"]["path"] = "../main"
        mutations.append(traversal)
        symlink_spell = copy.deepcopy(base)
        symlink_spell["dependencies"] = [
            _file("lib/../../escape", b"escape")
        ]
        mutations.append(symlink_spell)
        nul_argument = copy.deepcopy(base)
        nul_argument["argv"] = ["--value\x00ignored"]
        mutations.append(nul_argument)
        control_argument = copy.deepcopy(base)
        control_argument["argv"] = ["line\nbreak"]
        mutations.append(control_argument)

        for index, value in enumerate(mutations):
            with (
                self.subTest(index=index),
                self.assertRaises(RevRuntimeV1Error),
            ):
                RevRuntimeV1Spec.from_mapping(value)

    def test_runtime_options_are_format_specific_and_bound(self) -> None:
        cases = (
            {
                "format": "elf",
                "runtime": "native",
                "architecture": "aarch64",
            },
            {
                "format": "elf",
                "runtime": "qemu-user",
            },
            {
                "format": "java-class",
                "runtime": "java",
            },
            {
                "format": "wasm",
                "runtime": "node-wasi",
            },
            {
                "format": "pe",
                "runtime": "wine",
                "wasm_entrypoint": "_start",
            },
            {
                "format": "elf",
                "runtime": "qemu-user",
                "architecture": "aarch64",
                "qemu_ld_prefix": "missing",
            },
            {
                "format": "elf",
                "runtime": "native",
                "working_directory": "unbound",
            },
        )
        for index, values in enumerate(cases):
            selected = dict(values)
            with (
                self.subTest(index=index),
                self.assertRaises(RevRuntimeV1Error),
            ):
                build_rev_runtime_v1_spec(
                    source=_file("bin/main", b"main"),
                    **selected,
                )

    def test_protocol_and_schema_are_exact(self) -> None:
        spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_file("main", b"main"),
        ).to_dict()
        self.assertEqual(spec["protocol"], REV_RUNTIME_V1_PROTOCOL)
        for field, value in (
            ("protocol", "ctfos.rev.runtime.v2"),
            ("schema_version", 2),
        ):
            mutated = copy.deepcopy(spec)
            mutated[field] = value
            with self.assertRaises(RevRuntimeV1Error):
                RevRuntimeV1Spec.from_mapping(mutated)


if __name__ == "__main__":
    unittest.main()
