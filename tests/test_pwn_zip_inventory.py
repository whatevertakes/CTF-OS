from __future__ import annotations

import json
import os
import stat
import struct
import subprocess
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.sandbox.types import CommandSpec, ensure_foreground_command


class PwnZipInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = next(
            experiment
            for experiment in get_adapter("pwn").initial_observations()
            if experiment.id == "zip_inventory"
        )

    def _argv(self, source: Path) -> tuple[str, ...]:
        argv = tuple(
            argument.replace("{primary}", str(source))
            for argument in self.inventory.command_template
        )
        CommandSpec.create(argv)
        ensure_foreground_command(argv)
        return argv

    def _run(
        self,
        source: Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            self._argv(source),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=environment,
        )

    def _run_import_probe(
        self,
        source: Path,
        *,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[bytes]:
        product_argv = self._argv(source)
        self.assertEqual(product_argv[1:3], ("-I", "-c"))
        probe_argv = (
            product_argv[0],
            "-c",
            product_argv[3],
            product_argv[4],
        )
        return subprocess.run(
            probe_argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=environment,
        )

    @staticmethod
    def _records(payload: bytes) -> list[dict[str, object]]:
        payload.decode("ascii")
        return [json.loads(line) for line in payload.splitlines()]

    @staticmethod
    def _shadow_zipfile(
        root: Path,
        marker: Path,
    ) -> dict[str, str]:
        shadow = root / "shadow"
        shadow.mkdir()
        (shadow / "zipfile.py").write_text(
            "import os\n"
            "open(os.environ['CTFOS_ZIPFILE_IMPORT_MARKER'], 'wb').close()\n"
            "raise RuntimeError('zipfile parser was invoked')\n",
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(shadow)
        environment["CTFOS_ZIPFILE_IMPORT_MARKER"] = str(marker)
        return environment

    def test_normal_archive_is_deterministic_bounded_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-normal-"
        ) as temporary:
            root = Path(temporary)
            injection_marker = root / "must-not-exist"
            source = root / "archive;touch must-not-exist.zip"
            with zipfile.ZipFile(
                source,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr("bin/challenge", b"\x7fELFfixture")
                archive.writestr("README.txt", b"metadata only")
            os.chmod(source, 0o400)

            argv = self._argv(source)
            self.assertEqual(
                argv[:3],
                ("/usr/bin/python3", "-I", "-c"),
            )
            self.assertEqual(argv[-1], str(source))
            self.assertNotIn(str(source), argv[3])
            first = self._run(source)
            second = self._run(source)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stderr, b"")
            self.assertEqual(first.stdout, second.stdout)
            self.assertLessEqual(len(first.stdout), 64 * 1024)
            records = self._records(first.stdout)
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["mode"], "observed")
            self.assertTrue(records[0]["safe"])
            self.assertEqual(records[0]["entry_count"], 2)
            self.assertEqual(
                [record["name"] for record in records[1:]],
                ["bin/challenge", "README.txt"],
            )
            self.assertTrue(all(record["safe"] for record in records[1:]))
            self.assertTrue(
                all(
                    record["metadata_trust"]
                    == "central_directory_declared"
                    for record in records
                )
            )
            self.assertFalse(injection_marker.exists())
            self.assertEqual(set(root.iterdir()), {source})

    def test_paths_duplicates_symlink_device_and_control_names_are_unsafe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-unsafe-"
        ) as temporary:
            root = Path(temporary)
            source = root / "unsafe.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(source, "w") as archive:
                    archive.writestr("../escape", b"no extraction")
                    archive.writestr("/absolute", b"no extraction")
                    archive.writestr("dir\\backslash", b"no extraction")
                    archive.writestr("duplicate", b"one")
                    archive.writestr("duplicate", b"two")
                    archive.writestr("safe/\u202eexe", b"bidi")
                    link = zipfile.ZipInfo("link")
                    link.create_system = 3
                    link.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(link, b"../target")
                    device = zipfile.ZipInfo("device")
                    device.create_system = 3
                    device.external_attr = (stat.S_IFCHR | 0o600) << 16
                    archive.writestr(device, b"")

            result = self._run(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            records = self._records(result.stdout)
            self.assertEqual(records[0]["mode"], "unsafe")
            self.assertIn("unsafe_entries", records[0]["reasons"])
            entries = records[1:]
            self.assertIn("parent_path", entries[0]["reasons"])
            self.assertIn("absolute_path", entries[1]["reasons"])
            self.assertIn("backslash_path", entries[2]["reasons"])
            self.assertTrue(
                all(
                    "duplicate_name" in record["reasons"]
                    for record in entries[3:5]
                )
            )
            self.assertIn("control_or_bidi_name", entries[5]["reasons"])
            self.assertNotIn("\u202e", entries[5]["name"])
            self.assertIn("symlink_entry", entries[6]["reasons"])
            self.assertEqual(entries[6]["type"], "symlink")
            self.assertIn("unsupported_entry_type", entries[7]["reasons"])
            self.assertEqual(entries[7]["type"], "other")
            self.assertFalse((root.parent / "escape").exists())
            self.assertEqual(set(root.iterdir()), {source})

    def test_encryption_and_zip_bomb_metadata_are_unsafe_without_reads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-hazards-"
        ) as temporary:
            root = Path(temporary)
            encrypted = root / "encrypted.zip"
            with zipfile.ZipFile(encrypted, "w") as archive:
                archive.writestr("secret", b"declared encrypted")
            payload = bytearray(encrypted.read_bytes())
            local = payload.index(b"PK\x03\x04")
            central = payload.index(b"PK\x01\x02")
            local_flags = struct.unpack_from("<H", payload, local + 6)[0]
            central_flags = struct.unpack_from("<H", payload, central + 8)[0]
            struct.pack_into("<H", payload, local + 6, local_flags | 1)
            struct.pack_into("<H", payload, central + 8, central_flags | 1)
            encrypted.write_bytes(payload)

            encrypted_result = self._run(encrypted)
            self.assertEqual(
                encrypted_result.returncode,
                0,
                encrypted_result.stderr,
            )
            encrypted_records = self._records(encrypted_result.stdout)
            self.assertEqual(encrypted_records[0]["mode"], "unsafe")
            self.assertIn(
                "encrypted_entry",
                encrypted_records[1]["reasons"],
            )
            self.assertTrue(encrypted_records[1]["encrypted"])

            strong = root / "strong-encryption.zip"
            with zipfile.ZipFile(strong, "w") as archive:
                archive.writestr("secret", b"declared strong encryption")
            strong_payload = bytearray(strong.read_bytes())
            local = strong_payload.index(b"PK\x03\x04")
            central = strong_payload.index(b"PK\x01\x02")
            local_flags = struct.unpack_from(
                "<H",
                strong_payload,
                local + 6,
            )[0]
            central_flags = struct.unpack_from(
                "<H",
                strong_payload,
                central + 8,
            )[0]
            struct.pack_into("<H", strong_payload, local + 6, local_flags | 0x40)
            struct.pack_into(
                "<H",
                strong_payload,
                central + 8,
                central_flags | 0x40,
            )
            strong.write_bytes(strong_payload)

            strong_result = self._run(strong)
            self.assertEqual(strong_result.returncode, 0, strong_result.stderr)
            strong_records = self._records(strong_result.stdout)
            self.assertEqual(strong_records[0]["mode"], "unsafe")
            self.assertIn(
                "encrypted_entry",
                strong_records[1]["reasons"],
            )
            self.assertTrue(strong_records[1]["encrypted"])

            zip64_extra = root / "zip64-extra.zip"
            with zipfile.ZipFile(zip64_extra, "w") as archive:
                entry = zipfile.ZipInfo("declared-zip64")
                entry.extra = struct.pack("<HHQ", 0x0001, 8, 0)
                archive.writestr(entry, b"metadata")
            zip64_result = self._run(zip64_extra)
            self.assertEqual(zip64_result.returncode, 0, zip64_result.stderr)
            zip64_records = self._records(zip64_result.stdout)
            self.assertEqual(zip64_records[0]["mode"], "unsafe")
            self.assertIn(
                "zip64_entry_unsupported",
                zip64_records[1]["reasons"],
            )

            bomb = root / "bomb.zip"
            with zipfile.ZipFile(
                bomb,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr("bomb.bin", b"\x00" * (2 * 1024 * 1024))
            bomb_result = self._run(bomb)
            self.assertEqual(bomb_result.returncode, 0, bomb_result.stderr)
            bomb_records = self._records(bomb_result.stdout)
            self.assertEqual(bomb_records[0]["mode"], "unsafe")
            self.assertIn(
                "compression_ratio_limit_exceeded",
                bomb_records[1]["reasons"],
            )

    def test_nonzip_symlink_and_prebounded_limits_do_not_invoke_parser(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-preflight-"
        ) as temporary:
            root = Path(temporary)
            marker = root / "zipfile-imported"
            environment = self._shadow_zipfile(root, marker)

            nonzip = root / "not-an-archive.bin"
            nonzip.write_bytes(b"not a zip")
            nonzip_result = self._run_import_probe(
                nonzip,
                environment=environment,
            )
            self.assertEqual(nonzip_result.returncode, 0)
            self.assertEqual(
                self._records(nonzip_result.stdout)[0]["reason"],
                "unsupported_primary_format",
            )
            self.assertFalse(marker.exists())

            symlink = root / "archive.zip"
            symlink.symlink_to(nonzip)
            symlink_result = self._run_import_probe(
                symlink,
                environment=environment,
            )
            self.assertEqual(symlink_result.returncode, 2)
            self.assertEqual(symlink_result.stdout, b"")
            self.assertEqual(
                self._records(symlink_result.stderr)[0]["reason"],
                "symlink_source_binding",
            )
            self.assertFalse(marker.exists())

            too_many = root / "too-many.zip"
            with zipfile.ZipFile(too_many, "w") as archive:
                for ordinal in range(65):
                    archive.writestr(f"entry-{ordinal:02d}", b"")
            count_result = self._run_import_probe(
                too_many,
                environment=environment,
            )
            self.assertEqual(count_result.returncode, 0)
            count_record = self._records(count_result.stdout)[0]
            self.assertEqual(
                count_record["reason"],
                "entry_count_limit_exceeded",
            )
            self.assertEqual(count_record["entry_count"], 65)
            self.assertFalse(marker.exists())

            lying_count = root / "lying-count.zip"
            with zipfile.ZipFile(lying_count, "w") as archive:
                for ordinal in range(65):
                    archive.writestr(f"declared-one-{ordinal:02d}", b"")
            lying_payload = bytearray(lying_count.read_bytes())
            eocd = lying_payload.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            struct.pack_into("<H", lying_payload, eocd + 8, 1)
            struct.pack_into("<H", lying_payload, eocd + 10, 1)
            lying_count.write_bytes(lying_payload)
            lying_result = self._run_import_probe(
                lying_count,
                environment=environment,
            )
            self.assertEqual(lying_result.returncode, 0)
            self.assertEqual(
                self._records(lying_result.stdout)[0]["reason"],
                "entry_count_limit_exceeded",
            )
            self.assertFalse(marker.exists())

            oversized = root / "oversized.zip"
            with oversized.open("wb") as stream:
                stream.write(b"PK\x03\x04")
                stream.truncate(16 * 1024 * 1024 + 1)
            size_result = self._run_import_probe(
                oversized,
                environment=environment,
            )
            self.assertEqual(size_result.returncode, 0)
            self.assertEqual(
                self._records(size_result.stdout)[0]["reason"],
                "source_size_limit_exceeded",
            )
            self.assertFalse(marker.exists())

    def test_exact_magic_with_invalid_eocd_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-invalid-"
        ) as temporary:
            source = Path(temporary) / "invalid.zip"
            source.write_bytes(b"PK\x03\x04not-a-central-directory")
            result = self._run(source)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(
                self._records(result.stdout),
                [
                    {
                        "kind": "ctfos_pwn_zip_inventory",
                        "mode": "unsafe",
                        "reason": "invalid_end_of_central_directory",
                    }
                ],
            )

    def test_unexpected_metadata_exception_emits_stable_failure(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-unexpected-"
        ) as temporary:
            source = Path(temporary) / "private-source-name.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("private-entry-name", b"metadata")
            argv = self._argv(source)
            injected_code = argv[3].replace(
                "    before = os.fstat(descriptor)\n",
                "    raise RuntimeError('attacker-controlled detail')\n",
                1,
            )
            self.assertNotEqual(injected_code, argv[3])

            result = subprocess.run(
                (*argv[:3], injected_code, argv[4]),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(
                self._records(result.stderr),
                [
                    {
                        "kind": "ctfos_pwn_zip_inventory",
                        "mode": "error",
                        "reason": "inventory_failed_closed",
                    }
                ],
            )
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertNotIn(b"attacker-controlled", result.stderr)
            self.assertNotIn(str(source).encode(), result.stderr)

    def test_isolated_python_ignores_challenge_zipfile_shadow(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-isolated-import-"
        ) as temporary:
            root = Path(temporary)
            source = root / "archive.zip"
            marker = root / "shadow-imported"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("challenge", b"metadata")
            (root / "zipfile.py").write_text(
                "import os\n"
                "open(os.environ['CTFOS_SHADOW_MARKER'], 'wb').close()\n"
                "raise RuntimeError('untrusted shadow imported')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root)
            environment["CTFOS_SHADOW_MARKER"] = str(marker)

            result = subprocess.run(
                self._argv(source),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=environment,
                cwd=root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(self._records(result.stdout)[0]["mode"], "observed")
            self.assertFalse(marker.exists())

    def test_zip_suffix_blocks_elf_checksec_and_shebang_execution(self) -> None:
        observations = get_adapter("pwn").initial_observations()
        metadata = next(item for item in observations if item.id == "binary_metadata")
        baseline = next(item for item in observations if item.id == "runtime_baseline")
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-zip-polyglot-"
        ) as temporary:
            root = Path(temporary)
            checksec_marker = root / "checksec-invoked"
            execution_marker = root / "script-executed"
            checksec = root / "checksec"
            checksec.write_text(
                "#!/bin/sh\n: > \"$CTFOS_CHECKSEC_MARKER\"\n",
                encoding="utf-8",
            )
            os.chmod(checksec, 0o700)
            environment = dict(os.environ)
            environment["CTFOS_CHECKSEC_MARKER"] = str(checksec_marker)

            elf = root / "payload.ZIP"
            elf.write_bytes(Path("/bin/true").read_bytes())
            shebang = root / "payload.zip"
            shebang.write_text(
                "#!/bin/sh\n"
                f": > {execution_marker}\n",
                encoding="utf-8",
            )
            for source in (elf, shebang):
                os.chmod(source, 0o400)
                metadata_argv = tuple(
                    argument.replace("{primary}", str(source))
                    for argument in metadata.command_template
                ) + (str(checksec),)
                metadata_result = subprocess.run(
                    metadata_argv,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    env=environment,
                )
                baseline_argv = tuple(
                    argument.replace("{primary}", str(source))
                    for argument in baseline.command_template
                ) + (str(root),)
                baseline_result = subprocess.run(
                    baseline_argv,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                self.assertEqual(metadata_result.returncode, 0)
                self.assertEqual(
                    metadata_result.stdout,
                    b"ctfos_binary_metadata_mode=skipped\n"
                    b"ctfos_binary_metadata_reason=archive_primary_non_executable\n",
                )
                self.assertEqual(baseline_result.returncode, 0)
                self.assertEqual(
                    baseline_result.stdout,
                    b"ctfos_runtime_baseline_mode=skipped\n"
                    b"ctfos_runtime_baseline_reason=archive_primary_non_executable\n",
                )
            self.assertFalse(checksec_marker.exists())
            self.assertFalse(execution_marker.exists())
            self.assertEqual(
                list(root.glob("ctfos-pwn-baseline.*")),
                [],
            )


if __name__ == "__main__":
    unittest.main()
