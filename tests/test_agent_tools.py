from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ctf_os import agent_tools


class AgentToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_main(
        self,
        arguments: list[str],
        *,
        runner=subprocess.run,
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = agent_tools.main(
                arguments, root=self.root, runner=runner
            )
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_init_creates_contest_structure_under_incoming(self) -> None:
        exit_code, output, errors = self.run_main(
            ["init-contest", "Demo CTF", "--challenge", "web/Example"]
        )

        challenge_dir = (
            self.root / "incoming" / "Demo CTF" / "web" / "Example"
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue(challenge_dir.is_dir())
        self.assertEqual(
            sorted(path.relative_to(self.root) for path in self.root.rglob("*")),
            [
                Path("incoming"),
                Path("incoming/Demo CTF"),
                Path("incoming/Demo CTF/web"),
                Path("incoming/Demo CTF/web/Example"),
            ],
        )
        self.assertIn(str(challenge_dir), output)
        self.assertEqual(errors, "")

    def test_init_is_idempotent_and_preserves_downloaded_files(self) -> None:
        arguments = [
            "init-contest",
            "Demo CTF",
            "--challenge",
            "web/Example",
        ]
        first_exit_code, _, _ = self.run_main(arguments)
        challenge_file = (
            self.root
            / "incoming"
            / "Demo CTF"
            / "web"
            / "Example"
            / "challenge.bin"
        )
        original_contents = b"\x00CTF payload\xff"
        challenge_file.write_bytes(original_contents)

        second_exit_code, _, errors = self.run_main(arguments)

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(challenge_file.read_bytes(), original_contents)
        self.assertEqual(errors, "")

    def test_init_adds_another_problem_to_existing_category(self) -> None:
        self.run_main(
            ["init-contest", "Demo CTF", "--challenge", "web/Example"]
        )
        exit_code, _, errors = self.run_main(
            ["init-contest", "Demo CTF", "--challenge", "web/Second Problem"]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(
            (
                self.root / "incoming" / "Demo CTF" / "web" / "Example"
            ).is_dir()
        )
        self.assertTrue(
            (
                self.root
                / "incoming"
                / "Demo CTF"
                / "web"
                / "Second Problem"
            ).is_dir()
        )
        self.assertEqual(errors, "")

    def test_solve_empty_problem_directory_uses_expected_command(self) -> None:
        challenge_dir = (
            self.root / "incoming" / "Demo CTF" / "web" / "Example"
        )
        challenge_dir.mkdir(parents=True)
        commands: list[list[str]] = []

        def fake_runner(command):
            commands.append(list(command))
            return subprocess.CompletedProcess(command, 0)

        exit_code, output, errors = self.run_main(
            [
                "solve",
                "Demo CTF",
                "web",
                "Example",
                "문제 설명, nc example.test 31337, 기타 정보",
            ],
            runner=fake_runner,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(output, "")
        self.assertEqual(errors, "")
        self.assertEqual(
            commands,
            [
                [
                    "codex",
                    "-C",
                    str(challenge_dir),
                    (
                        "Demo CTF의 web 카테고리 Example 문제다.\n\n"
                        "문제 설명, nc example.test 31337, 기타 정보"
                    ),
                ]
            ],
        )
        self.assertEqual(list(challenge_dir.iterdir()), [])

    def test_solve_propagates_codex_exit_code(self) -> None:
        (
            self.root / "incoming" / "Demo CTF" / "web" / "Example"
        ).mkdir(parents=True)

        def fake_runner(command):
            return subprocess.CompletedProcess(command, 23)

        exit_code, _, _ = self.run_main(
            ["solve", "Demo CTF", "web", "Example", "details"],
            runner=fake_runner,
        )

        self.assertEqual(exit_code, 23)

    def test_solve_rejects_missing_problem_directory(self) -> None:
        exit_code, output, errors = self.run_main(
            ["solve", "Demo CTF", "web", "Missing", "details"],
            runner=lambda command: self.fail("runner must not be called"),
        )

        self.assertNotEqual(exit_code, 0)
        self.assertEqual(output, "")
        self.assertIn("문제 폴더가 존재하지 않습니다", errors)

    def test_solve_reports_missing_codex(self) -> None:
        (
            self.root / "incoming" / "Demo CTF" / "web" / "Example"
        ).mkdir(parents=True)

        def missing_runner(command):
            raise FileNotFoundError("codex")

        exit_code, output, errors = self.run_main(
            ["solve", "Demo CTF", "web", "Example", "details"],
            runner=missing_runner,
        )

        self.assertEqual(exit_code, 127)
        self.assertEqual(output, "")
        self.assertIn("Codex 실행 파일을 찾을 수 없습니다", errors)

    def test_init_rejects_invalid_challenge_specs(self) -> None:
        invalid_specs = [
            "",
            "web",
            "web/",
            "/Example",
            "web/Example/extra",
            r"web\Example",
            "../Example",
            "web/..",
        ]

        for spec in invalid_specs:
            with self.subTest(spec=spec):
                exit_code, _, errors = self.run_main(
                    [
                        "init-contest",
                        "Demo CTF",
                        "--challenge",
                        spec,
                    ]
                )
                self.assertNotEqual(exit_code, 0)
                self.assertIn("오류:", errors)

        self.assertEqual(list(self.root.iterdir()), [])

    def test_rejects_invalid_individual_names(self) -> None:
        invalid_names = ["", "   ", ".", "..", "/tmp", r"foo\bar", "a/b"]

        for name in invalid_names:
            with self.subTest(command="init", name=name):
                exit_code, _, errors = self.run_main(
                    [
                        "init-contest",
                        name,
                        "--challenge",
                        "web/Example",
                    ]
                )
                self.assertNotEqual(exit_code, 0)
                self.assertIn("오류:", errors)

        (
            self.root / "incoming" / "Demo CTF" / "web" / "Example"
        ).mkdir(parents=True)
        for name in invalid_names:
            with self.subTest(command="solve", name=name):
                exit_code, _, errors = self.run_main(
                    ["solve", "Demo CTF", "web", name, "details"],
                    runner=lambda command: self.fail("runner must not be called"),
                )
                self.assertNotEqual(exit_code, 0)
                self.assertIn("오류:", errors)

    def test_rejects_symlink_escape_from_workspace(self) -> None:
        outside = Path(self.temporary_directory.name).parent / (
            f"{Path(self.temporary_directory.name).name}-outside"
        )
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        incoming = self.root / "incoming"
        incoming.mkdir()
        (incoming / "Demo CTF").symlink_to(
            outside, target_is_directory=True
        )

        exit_code, _, errors = self.run_main(
            ["init-contest", "Demo CTF", "--challenge", "web/Example"]
        )

        self.assertNotEqual(exit_code, 0)
        self.assertIn("현재 작업공간 밖", errors)
        self.assertEqual(list(outside.iterdir()), [])

    def test_existing_file_in_directory_path_is_reported(self) -> None:
        incoming = self.root / "incoming"
        incoming.mkdir()
        (incoming / "Demo CTF").write_text("not a directory")

        exit_code, output, errors = self.run_main(
            ["init-contest", "Demo CTF", "--challenge", "web/Example"]
        )

        self.assertNotEqual(exit_code, 0)
        self.assertEqual(output, "")
        self.assertIn("문제 폴더를 생성할 수 없습니다", errors)


if __name__ == "__main__":
    unittest.main()
