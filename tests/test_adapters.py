from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.sandbox.types import CommandSpec, ensure_foreground_command


class AdapterTests(unittest.TestCase):
    def test_all_supported_categories_have_complete_contracts(self) -> None:
        for category in ("pwn", "rev", "crypto", "forensic", "web", "misc"):
            with self.subTest(category=category):
                adapter = get_adapter(category)
                self.assertTrue(adapter.initial_observations())
                self.assertTrue(adapter.progress_markers())
                self.assertTrue(adapter.failure_labels())
                self.assertTrue(adapter.captain_guidance())
                self.assertGreaterEqual(
                    adapter.proof_policy().clean_repetitions, 1
                )

    def test_competition_category_labels_resolve_without_changing_state_names(self) -> None:
        aliases = {
            "System Hacking": "pwn",
            "system-hacking": "pwn",
            "binary exploitation": "pwn",
            "Reverse Engineering": "reversing",
            "reverse-engineering": "reversing",
            "Cryptography": "crypto",
            "Digital Forensics": "forensics",
            "digital-forensics": "forensics",
            "Web Hacking": "web",
            "web security": "web",
            "Miscellaneous": "misc",
            "Steganography": "misc",
        }
        for label, expected in aliases.items():
            with self.subTest(label=label):
                self.assertEqual(get_adapter(label).name, expected)

    def test_pwn_markers_are_capabilities_not_a_required_ladder(self) -> None:
        adapter = get_adapter("pwn")
        keys = {marker.key for marker in adapter.progress_markers()}
        self.assertIn("control", keys)
        self.assertIn("flag_read", keys)
        self.assertNotIn("ordered", adapter.captain_guidance().lower())

    def test_pwn_runtime_baseline_is_bounded_and_path_safe(self) -> None:
        observations = get_adapter("pwn").initial_observations()
        self.assertEqual(
            [experiment.id for experiment in observations],
            ["binary_metadata", "runtime_baseline", "zip_inventory"],
        )
        metadata = next(
            experiment
            for experiment in observations
            if experiment.id == "binary_metadata"
        )
        baseline = next(
            experiment
            for experiment in observations
            if experiment.id == "runtime_baseline"
        )
        zip_inventory = next(
            experiment
            for experiment in observations
            if experiment.id == "zip_inventory"
        )
        primary = "/challenge/name with 'quotes' and $shell"
        metadata_argv = tuple(
            argument.replace("{primary}", primary)
            for argument in metadata.command_template
        )
        argv = tuple(
            argument.replace("{primary}", primary)
            for argument in baseline.command_template
        )
        zip_argv = tuple(
            argument.replace("{primary}", primary)
            for argument in zip_inventory.command_template
        )

        self.assertEqual(metadata_argv[:2], ("/bin/sh", "-lc"))
        self.assertEqual(metadata_argv[-1], primary)
        self.assertEqual(metadata_argv[-2], "ctfos-pwn-binary-metadata")
        self.assertNotIn(primary, metadata_argv[2])
        self.assertIn("/usr/bin/checksec", metadata_argv[2])
        self.assertIn('exec "$checksec_path"', metadata_argv[2])
        self.assertIn("/usr/bin/od -An -N4 -tu1", metadata_argv[2])
        self.assertEqual(metadata.resource_class, "light")
        self.assertFalse(metadata.requires_network)
        CommandSpec.create(metadata_argv)
        ensure_foreground_command(metadata_argv)

        self.assertEqual(argv[:2], ("/bin/sh", "-lc"))
        self.assertEqual(argv[-1], primary)
        self.assertEqual(argv[-2], "ctfos-pwn-runtime-baseline")
        self.assertEqual(baseline.timeout_s, 15)
        self.assertEqual(baseline.resource_class, "light")
        self.assertNotIn(primary, argv[2])
        self.assertIn(
            "/usr/bin/timeout --signal=TERM --kill-after=1 3",
            argv[2],
        )
        self.assertIn("--kill-after=1", argv[2])
        self.assertNotIn("ulimit -f", argv[2])
        self.assertIn("/usr/bin/head -c 65536", argv[2])
        self.assertIn("ctfos_runtime_baseline_exit=", argv[2])
        self.assertIn('/usr/bin/cp -- "$target" "$staged"', argv[2])
        self.assertIn('/usr/bin/chmod 0500 -- "$staged"', argv[2])
        self.assertNotIn('chmod 0500 -- "$target"', argv[2])
        self.assertFalse(baseline.requires_network)
        CommandSpec.create(argv)
        ensure_foreground_command(argv)

        self.assertEqual(
            zip_argv[:3],
            ("/usr/bin/python3", "-I", "-c"),
        )
        self.assertEqual(zip_argv[-1], primary)
        self.assertNotIn(primary, zip_argv[3])
        self.assertIn("ZipFile", zip_argv[3])
        self.assertIn("archive.infolist()", zip_argv[3])
        for forbidden in (
            "archive.open(",
            "archive.read(",
            ".extract(",
            "testzip(",
        ):
            self.assertNotIn(forbidden, zip_argv[3])
        self.assertEqual(zip_inventory.timeout_s, 15)
        self.assertEqual(zip_inventory.resource_class, "light")
        self.assertFalse(zip_inventory.requires_network)
        CommandSpec.create(zip_argv)
        ensure_foreground_command(zip_argv)

    def test_pwn_mode_0400_elf_runs_from_private_staged_copy(
        self,
    ) -> None:
        observations = get_adapter("pwn").initial_observations()
        metadata = next(
            experiment
            for experiment in observations
            if experiment.id == "binary_metadata"
        )
        baseline = next(
            experiment
            for experiment in observations
            if experiment.id == "runtime_baseline"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-immutable-elf-test-"
        ) as temporary:
            root = Path(temporary)
            target = root / "immutable-true"
            target.write_bytes(Path("/bin/true").read_bytes())
            os.chmod(target, 0o400)

            fake_bin = root / "bin"
            fake_bin.mkdir()
            checksec = fake_bin / "checksec"
            checksec.write_text(
                "#!/bin/sh\n"
                "printf 'checksec-fixture-ok\\n'\n"
                "printf '%s\\n' \"$@\"\n"
                ": > \"$CTFOS_TEST_CHECKSEC_MARKER\"\n",
                encoding="utf-8",
            )
            os.chmod(checksec, 0o700)
            checksec_marker = root / "checksec-invoked"
            environment = dict(os.environ)
            environment["CTFOS_TEST_CHECKSEC_MARKER"] = str(
                checksec_marker
            )

            metadata_argv = tuple(
                argument.replace("{primary}", str(target))
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
                argument.replace("{primary}", str(target))
                for argument in baseline.command_template
            ) + (str(root),)
            baseline_result = subprocess.run(
                baseline_argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

            self.assertEqual(target.stat().st_mode & 0o777, 0o400)
            self.assertTrue(checksec_marker.is_file())
            self.assertEqual(
                list(root.glob("ctfos-pwn-baseline.*")),
                [],
            )

        self.assertEqual(
            metadata_result.returncode,
            0,
            metadata_result.stderr,
        )
        self.assertEqual(metadata_result.stderr, b"")
        self.assertIn(b"checksec-fixture-ok\n", metadata_result.stdout)
        self.assertIn(
            f"--file={target}".encode("utf-8"),
            metadata_result.stdout,
        )
        self.assertEqual(
            baseline_result.returncode,
            0,
            baseline_result.stderr,
        )
        self.assertEqual(baseline_result.stderr, b"")
        self.assertIn(
            b"ctfos_runtime_baseline_exit=0 pipe_exit=0\n",
            baseline_result.stdout,
        )

    def test_pwn_unsupported_regular_primary_is_not_checked_or_executed(
        self,
    ) -> None:
        observations = get_adapter("pwn").initial_observations()
        metadata = next(
            experiment
            for experiment in observations
            if experiment.id == "binary_metadata"
        )
        baseline = next(
            experiment
            for experiment in observations
            if experiment.id == "runtime_baseline"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-unsupported-primary-test-"
        ) as temporary:
            root = Path(temporary)
            execution_marker = root / "unsupported-was-executed"
            target = root / "share.zip"
            target.write_text(
                f"/usr/bin/touch {execution_marker}\n",
                encoding="utf-8",
            )
            os.chmod(target, 0o400)

            fake_bin = root / "bin"
            fake_bin.mkdir()
            checksec = fake_bin / "checksec"
            checksec_marker = root / "checksec-was-invoked"
            checksec.write_text(
                "#!/bin/sh\n"
                f": > {checksec_marker}\n",
                encoding="utf-8",
            )
            os.chmod(checksec, 0o700)
            metadata_argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in metadata.command_template
            ) + (str(checksec),)
            metadata_result = subprocess.run(
                metadata_argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            baseline_argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in baseline.command_template
            ) + (str(root),)
            baseline_result = subprocess.run(
                baseline_argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

            self.assertFalse(checksec_marker.exists())
            self.assertFalse(execution_marker.exists())
            self.assertEqual(target.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                list(root.glob("ctfos-pwn-baseline.*")),
                [],
            )

        self.assertEqual(metadata_result.returncode, 0)
        self.assertEqual(metadata_result.stderr, b"")
        self.assertEqual(
            metadata_result.stdout,
            b"ctfos_binary_metadata_mode=skipped\n"
            b"ctfos_binary_metadata_reason=archive_primary_non_executable\n",
        )
        self.assertEqual(baseline_result.returncode, 0)
        self.assertEqual(baseline_result.stderr, b"")
        self.assertEqual(
            baseline_result.stdout,
            b"ctfos_runtime_baseline_mode=skipped\n"
            b"ctfos_runtime_baseline_reason=archive_primary_non_executable\n",
        )

    def test_pwn_non_regular_and_symlink_bindings_are_safe(self) -> None:
        observations = get_adapter("pwn").initial_observations()
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-binding-applicability-test-"
        ) as temporary:
            root = Path(temporary)
            directory = root / "challenge"
            directory.mkdir()
            sentinel = "must-not-be-traversed-by-pwn-probes"
            (directory / "nested.bin").write_text(
                sentinel,
                encoding="utf-8",
            )
            regular = root / "regular"
            regular.write_bytes(Path("/bin/true").read_bytes())
            os.chmod(regular, 0o400)
            symlink = root / "primary"
            symlink.symlink_to(regular)

            for experiment in observations:
                with self.subTest(
                    experiment=experiment.id,
                    binding="directory",
                ):
                    argv = tuple(
                        argument.replace("{primary}", str(directory))
                        for argument in experiment.command_template
                    )
                    if experiment.id == "runtime_baseline":
                        argv += (str(root),)
                    result = subprocess.run(
                        argv,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stderr, b"")
                    if experiment.id == "zip_inventory":
                        self.assertEqual(
                            json.loads(result.stdout),
                            {
                                "kind": "ctfos_pwn_zip_inventory",
                                "mode": "skipped",
                                "reason": "no_regular_source_binding",
                            },
                        )
                    else:
                        prefix = (
                            "ctfos_binary_metadata"
                            if experiment.id == "binary_metadata"
                            else "ctfos_runtime_baseline"
                        )
                        self.assertEqual(
                            result.stdout.decode("utf-8"),
                            f"{prefix}_mode=skipped\n"
                            f"{prefix}_reason=no_regular_source_binding\n",
                        )
                    self.assertNotIn(
                        sentinel.encode("utf-8"),
                        result.stdout,
                    )

                with self.subTest(
                    experiment=experiment.id,
                    binding="symlink",
                ):
                    argv = tuple(
                        argument.replace("{primary}", str(symlink))
                        for argument in experiment.command_template
                    )
                    if experiment.id == "runtime_baseline":
                        argv += (str(root),)
                    result = subprocess.run(
                        argv,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    if experiment.id == "zip_inventory":
                        self.assertEqual(
                            json.loads(result.stderr),
                            {
                                "kind": "ctfos_pwn_zip_inventory",
                                "mode": "error",
                                "reason": "symlink_source_binding",
                            },
                        )
                    else:
                        prefix = (
                            "ctfos_binary_metadata"
                            if experiment.id == "binary_metadata"
                            else "ctfos_runtime_baseline"
                        )
                        self.assertEqual(
                            result.stderr.decode("utf-8"),
                            f"{prefix}_error=symlink_source_binding\n",
                        )

    def test_pwn_runtime_baseline_drains_an_unbounded_menu_without_disk_capture(
        self,
    ) -> None:
        baseline = next(
            experiment
            for experiment in get_adapter("pwn").initial_observations()
            if experiment.id == "runtime_baseline"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-pwn-baseline-test-"
        ) as temporary:
            target = Path(temporary) / "menu"
            target.write_text(
                "#!/bin/sh\nexec /usr/bin/yes MENU\n",
                encoding="utf-8",
            )
            os.chmod(target, 0o400)
            argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in baseline.command_template
            ) + (str(Path(temporary)),)
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                list(Path(temporary).glob("ctfos-pwn-baseline.*")),
                [],
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(len(result.stdout), 65_700)
        self.assertTrue(result.stdout.startswith(b"MENU\n"))
        self.assertIn(b"ctfos_runtime_baseline_exit=", result.stdout)
        self.assertIn(b"pipe_exit=0", result.stdout)

    def test_crypto_static_scan_accepts_python2_without_execution(self) -> None:
        scan = next(
            experiment
            for experiment in get_adapter("crypto").initial_observations()
            if experiment.id == "source_parameters"
        )
        command = scan.command_template[2]
        self.assertEqual(scan.command_template[:2], ("/bin/sh", "-lc"))
        for forbidden in (
            "/usr/bin/python",
            "/bin/python",
            "python2 -m",
            "python3 -m",
            "py_compile",
            "ast.parse",
            "eval ",
            "exec ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, command)
        self.assertIn('/usr/bin/head -c 512 -- "$target"', command)
        self.assertIn("rg --text --quiet", command)
        self.assertFalse(scan.requires_network)
        self.assertEqual(scan.timeout_s, 30)

        with tempfile.TemporaryDirectory(
            prefix="ctfos-crypto-static-scan-test-"
        ) as temporary:
            root = Path(temporary)
            marker = root / "source-was-executed"
            source = root / "sleeping_guard.py"
            source.write_text(
                "#!/usr/bin/env python2\n"
                "from Crypto.Cipher import AES\n"
                "modulus = 3233\n"
                "public_exponent = 17\n"
                "print 'ciphertext', modulus\n"
                f"open({str(marker)!r}, 'w').write('unsafe')\n",
                encoding="utf-8",
            )
            argv = tuple(
                argument.replace("{primary}", str(source))
                for argument in scan.command_template
            )
            self.assertEqual(argv[-1], str(source))
            self.assertNotIn(str(source), argv[2])
            CommandSpec.create(argv)
            ensure_foreground_command(argv)
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

        output = result.stdout.decode("utf-8")
        self.assertIn("ctfos_scan_mode=static", output)
        self.assertIn("ctfos_source_language=python", output)
        dialect_header = "ctfos_source_dialect_hint=python2_shebang"
        self.assertIn(dialect_header, output)
        self.assertIn(dialect_header.encode("utf-8"), result.stdout[:256])
        self.assertIn("2:from Crypto.Cipher import AES", output)
        self.assertIn("3:modulus = 3233", output)
        self.assertIn("5:print 'ciphertext', modulus", output)
        self.assertLessEqual(len(result.stdout), 65_536)

    def test_crypto_static_scan_uses_only_versioned_first_line_shebang(
        self,
    ) -> None:
        scan = next(
            experiment
            for experiment in get_adapter("crypto").initial_observations()
            if experiment.id == "source_parameters"
        )
        cases = (
            (
                "python3",
                "parameters.py",
                "#!/usr/bin/env python3\nmodulus = 3233\n",
                "python3_shebang",
            ),
            (
                "python2_env_split_args",
                "parameters.py",
                "#!/usr/bin/env -S python2 -u\nmodulus = 3233\n",
                "python2_shebang",
            ),
            (
                "python2_absolute_versioned",
                "parameters.py",
                "#!/usr/bin/python2.7\nmodulus = 3233\n",
                "python2_shebang",
            ),
            (
                "python2_prefix_is_not_interpreter",
                "parameters.py",
                "#!/usr/bin/python2extra\nmodulus = 3233\n",
                "unknown",
            ),
            (
                "generic_python",
                "parameters.py",
                "#!/usr/bin/env python\nmodulus = 3233\n",
                "unknown",
            ),
            (
                "no_shebang",
                "parameters.py",
                "def identity(value: int) -> int:\n    return value\n",
                "unknown",
            ),
            (
                "sage_without_shebang",
                "parameters.sage",
                "modulus = 3233\n",
                "unknown",
            ),
            (
                "python3_with_python2_body_noise",
                "parameters.py",
                "#!/usr/bin/env python3\n"
                "legacy_example = \"\"\"\n"
                "#!/usr/bin/env python2\n"
                "print 'old syntax'\n"
                "\"\"\"\n"
                "modulus = 3233\n",
                "python3_shebang",
            ),
            (
                "non_python",
                "parameters.json",
                '{"runtime": "python2", "modulus": 3233}\n',
                None,
            ),
        )

        for name, filename, source_text, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(
                prefix="ctfos-crypto-dialect-hint-test-"
            ) as temporary:
                source = Path(temporary) / filename
                source.write_text(source_text, encoding="utf-8")
                argv = tuple(
                    argument.replace("{primary}", str(source))
                    for argument in scan.command_template
                )
                result = subprocess.run(
                    argv,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                output = result.stdout.decode("utf-8")
                dialect_headers = tuple(
                    line
                    for line in output.splitlines()
                    if line.startswith("ctfos_source_dialect_hint=")
                )
                if expected is None:
                    self.assertEqual(dialect_headers, ())
                else:
                    self.assertEqual(
                        dialect_headers,
                        (f"ctfos_source_dialect_hint={expected}",),
                    )

    def test_crypto_guidance_routes_source_dialect_safely(self) -> None:
        guidance = get_adapter("crypto").captain_guidance()
        self.assertIn(
            "ctfos_source_dialect_hint=python2_shebang",
            guidance,
        )
        self.assertIn("Python 3 `ast.parse`", guidance)
        self.assertIn("`unknown` does not mean Python 3", guidance)
        self.assertIn("`SyntaxError`", guidance)
        self.assertIn("parser/dialect mismatch", guidance)

    def test_crypto_static_scan_skips_directory_without_traversal(
        self,
    ) -> None:
        scan = next(
            experiment
            for experiment in get_adapter("crypto").initial_observations()
            if experiment.id == "source_parameters"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-crypto-static-scan-directory-test-"
        ) as temporary:
            target = Path(temporary) / "challenge"
            target.mkdir()
            nested_content = "must-not-be-read-or-reported"
            (target / "parameters.py").write_text(
                f"secret_parameter = {nested_content!r}\n",
                encoding="utf-8",
            )
            argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in scan.command_template
            )
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            b"ctfos_scan_mode=skipped\n"
            b"ctfos_static_scan_reason=no_regular_source_binding\n",
        )
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(nested_content.encode("utf-8"), result.stdout)

    def test_crypto_static_scan_rejects_symlink_fail_closed(self) -> None:
        scan = next(
            experiment
            for experiment in get_adapter("crypto").initial_observations()
            if experiment.id == "source_parameters"
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-crypto-static-scan-symlink-test-"
        ) as temporary:
            root = Path(temporary)
            source = root / "parameters.py"
            source.write_text("modulus = 3233\n", encoding="utf-8")
            target = root / "primary.py"
            target.symlink_to(source)
            argv = tuple(
                argument.replace("{primary}", str(target))
                for argument in scan.command_template
            )
            result = subprocess.run(
                argv,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            result.stderr,
            b"ctfos_static_scan_error=not_regular_file\n",
        )

    def test_web_intake_never_makes_an_implicit_remote_request(self) -> None:
        adapter = get_adapter("web")
        for experiment in adapter.initial_observations():
            self.assertFalse(experiment.requires_network)
        marker_keys = {marker.key for marker in adapter.progress_markers()}
        self.assertIn("endpoint_observed", marker_keys)
        self.assertIn("auth_state_captured", marker_keys)
        self.assertIn("impact_verified", marker_keys)
        guidance = adapter.captain_guidance()
        self.assertIn("--session attacker|user|admin", guidance)
        self.assertIn("request.py URL -X METHOD", guidance)
        self.assertIn("request.py http://target/path -X GET", guidance)
        self.assertIn("never use `--url`", guidance)
        self.assertIn("Omit `--session` from generic command actions", guidance)
        self.assertIn("engine-owned typed Web gate", guidance)
        self.assertNotIn("-X GET --session", guidance)
        self.assertIn("ctf-sqlite-readonly", guidance)
        self.assertIn("allowlisted HTTP", guidance)

    def test_forensics_intake_uses_bounded_read_only_evidence_index(
        self,
    ) -> None:
        experiments = get_adapter("forensics").initial_observations()
        self.assertEqual(len(experiments), 1)
        inventory = experiments[0]
        self.assertEqual(inventory.id, "file_inventory")
        self.assertEqual(
            inventory.command_template,
            (
                "/usr/bin/python3",
                "/opt/ctf-templates/forensic/evidence_index.py",
                "--root",
                "/challenge",
                "--tree",
                "/work/.ctf/challenge.tree",
                "--metadata",
                "/work/.ctf/challenge.json",
            ),
        )
        self.assertFalse(inventory.requires_network)
        self.assertIn("coverage", inventory.expected_observation)

    def test_misc_intake_preserves_three_independent_modality_probes(
        self,
    ) -> None:
        adapter = get_adapter("misc")
        experiments = adapter.initial_observations()

        self.assertEqual(
            [item.id for item in experiments],
            ["typed_inventory", "primary_magic", "primary_strings"],
        )
        self.assertTrue(
            all(not item.requires_network for item in experiments)
        )
        self.assertEqual(
            experiments[0].command_template[1],
            "/opt/ctf-templates/forensic/evidence_index.py",
        )
        self.assertEqual(experiments[1].command_template[:2], ("/bin/sh", "-lc"))
        self.assertIn("/usr/bin/file", experiments[1].command_template[2])
        self.assertEqual(experiments[2].command_template[:2], ("/bin/sh", "-lc"))
        self.assertIn("/usr/bin/head -c 65536", experiments[2].command_template[2])

        guidance = adapter.captain_guidance()
        for prior in (
            "stego=0.35",
            "custom_protocol=0.25",
            "audio_signal=0.15",
            "jail=0.10",
            "ppc=0.10",
            "other=0.05",
        ):
            self.assertIn(prior, guidance)
        self.assertIn("three independent", guidance)
        self.assertIn("two independent observations", guidance)

    def test_misc_strings_probe_keeps_primary_out_of_shell_source(self) -> None:
        probe = next(
            item
            for item in get_adapter("misc").initial_observations()
            if item.id == "primary_strings"
        )
        primary = "/challenge/name with 'quotes' and $shell"
        argv = tuple(
            argument.replace("{primary}", primary)
            for argument in probe.command_template
        )

        self.assertEqual(argv[-1], primary)
        self.assertEqual(argv[-2], "ctfos-misc-primary-strings")
        self.assertNotIn(primary, argv[2])
        CommandSpec.create(argv)
        ensure_foreground_command(argv)

    def test_misc_primary_probes_skip_directory_without_traversal(
        self,
    ) -> None:
        probes = tuple(
            item
            for item in get_adapter("misc").initial_observations()
            if item.id in {"primary_magic", "primary_strings"}
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-misc-primary-directory-test-"
        ) as temporary:
            target = Path(temporary) / "challenge"
            target.mkdir()
            sentinel = "must-not-be-read-by-misc-primary-probes"
            (target / "nested.txt").write_text(
                sentinel,
                encoding="utf-8",
            )
            for probe in probes:
                with self.subTest(probe=probe.id):
                    argv = tuple(
                        argument.replace("{primary}", str(target))
                        for argument in probe.command_template
                    )
                    result = subprocess.run(
                        argv,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    prefix = (
                        "ctfos_primary_magic"
                        if probe.id == "primary_magic"
                        else "ctfos_primary_strings"
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(
                        result.stdout.decode("utf-8"),
                        f"{prefix}_mode=skipped\n"
                        f"{prefix}_reason=no_regular_source_binding\n",
                    )
                    self.assertNotIn(
                        sentinel.encode("utf-8"),
                        result.stdout,
                    )

    def test_misc_primary_probes_reject_symlinks_fail_closed(self) -> None:
        probes = tuple(
            item
            for item in get_adapter("misc").initial_observations()
            if item.id in {"primary_magic", "primary_strings"}
        )
        with tempfile.TemporaryDirectory(
            prefix="ctfos-misc-primary-symlink-test-"
        ) as temporary:
            root = Path(temporary)
            source = root / "artifact.txt"
            source.write_text(
                "printable-sentinel-content\n",
                encoding="utf-8",
            )
            os.chmod(source, 0o400)
            target = root / "primary"
            target.symlink_to(source)
            for probe in probes:
                with self.subTest(probe=probe.id):
                    argv = tuple(
                        argument.replace("{primary}", str(target))
                        for argument in probe.command_template
                    )
                    result = subprocess.run(
                        argv,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    prefix = (
                        "ctfos_primary_magic"
                        if probe.id == "primary_magic"
                        else "ctfos_primary_strings"
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(
                        result.stderr.decode("utf-8"),
                        f"{prefix}_error=symlink_source_binding\n",
                    )

    def test_unknown_category_keeps_single_generic_inventory(self) -> None:
        adapter = get_adapter("unknown-category")
        self.assertEqual(adapter.name, "misc")
        self.assertEqual(
            [item.id for item in adapter.initial_observations()],
            ["inventory"],
        )


if __name__ == "__main__":
    unittest.main()
