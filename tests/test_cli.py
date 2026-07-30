from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ctf_os import cli
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.live_broker import MAX_INSPECT_PAGE_ITEMS
from ctf_os.models import ChallengeIdentity, GoalStatus, HypothesisStatus
from ctf_os.sandbox.daemon import CapabilityAuthority
from ctf_os.store import ChallengeLock, StateStore

IMAGE_DIGEST = "sha256:" + "a" * 64


class CLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ("국내 CTF", "rev", "문제 1")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_cli(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(arguments, root=self.root)
        return status, stdout.getvalue(), stderr.getvalue()

    def add(self) -> None:
        status, _, errors = self.run_cli(
            [
                "add-challenge",
                *self.identity,
                "--prompt",
                "분석하고 solver를 만들어라",
            ]
        )
        self.assertEqual(status, 0, errors)

    def test_human_folder_prompt_status_and_budget_workflow(self) -> None:
        self.add()
        self.assertTrue(
            (
                self.root
                / "incoming"
                / self.identity[0]
                / self.identity[1]
                / self.identity[2]
            ).is_dir()
        )
        status, output, errors = self.run_cli(
            ["status", self.identity[0]]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("TRIAGING", output)
        status, output, errors = self.run_cli(
            ["budget-reset", *self.identity]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("28800", output)

    def test_safe_contest_and_challenge_flag_formats_are_persisted(self) -> None:
        status, _, errors = self.run_cli(
            [
                "add-challenge",
                *self.identity,
                "--prompt",
                "solve",
                "--contest-flag-prefix",
                "KCTF",
                "--flag-prefix",
                "TASK",
                "--flag-alphabet",
                "alnum_",
                "--flag-min-inner",
                "4",
                "--flag-max-inner",
                "64",
            ]
        )
        self.assertEqual(status, 0, errors)
        store = StateStore(self.root)
        first = store.load(ChallengeIdentity(*self.identity))
        self.assertEqual(
            first.metadata["challenge_flag_format"]["prefix"],
            "TASK",
        )
        self.assertEqual(
            first.metadata["contest_flag_format"]["prefix"],
            "KCTF",
        )

        second_identity = (self.identity[0], "web", "문제 2")
        status, _, errors = self.run_cli(
            [
                "add-challenge",
                *second_identity,
                "--prompt",
                "solve second",
            ]
        )
        self.assertEqual(status, 0, errors)
        second = store.load(ChallengeIdentity(*second_identity))
        self.assertNotIn("challenge_flag_format", second.metadata)
        self.assertEqual(
            second.metadata["contest_flag_format"]["prefix"],
            "KCTF",
        )

    def test_plain_status_escapes_model_control_characters(self) -> None:
        self.add()
        engine = ChallengeEngine(self.root)
        engine.manage_goal(
            ChallengeIdentity(*self.identity),
            action="create",
            goal_id="G-terminal-safe",
            description="safe\x1b]52;c;UE9JU09O\x07tail",
            activate=True,
        )

        status, output, errors = self.run_cli(
            ["status", self.identity[0]]
        )

        self.assertEqual(status, 0, errors)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x07", output)
        self.assertIn(r"\x1b]52;c;UE9JU09O\x07", output)

    def test_no_contest_wide_automatic_challenge_runner_is_exposed(self) -> None:
        self.assertNotIn("run-contest", cli.build_parser().format_help())

    def test_status_rejects_non_finite_watch_intervals(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(interval=value):
                status, _, errors = self.run_cli(
                    ["status", self.identity[0], f"--interval={value}"]
                )
                self.assertNotEqual(status, 0)
                self.assertIn("유한한 양수", errors)

    def test_inspect_summary_and_explicit_empty_page(self) -> None:
        self.add()
        status, output, errors = self.run_cli(
            ["inspect", *self.identity, "summary"]
        )
        self.assertEqual(status, 0, errors)
        summary = json.loads(output)
        self.assertEqual(summary["section"], "summary")
        self.assertIn("goals", summary["counts"])

        status, output, errors = self.run_cli(
            [
                "inspect",
                *self.identity,
                "submissions",
                "--offset",
                "0",
                "--limit",
                "1",
            ]
        )
        self.assertEqual(status, 0, errors)
        page = json.loads(output)
        self.assertEqual(page["items"], [])
        self.assertEqual(page["offset"], 0)
        self.assertEqual(page["limit"], 1)
        self.assertEqual(page["total"], 0)
        self.assertIsNone(page["next_offset"])

    def test_inspect_cli_rejects_out_of_range_pagination(self) -> None:
        parser = cli.build_parser()
        invalid_values = ("0", str(MAX_INSPECT_PAGE_ITEMS + 1), "1.5")
        for value in invalid_values:
            with (
                self.subTest(limit=value),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args(
                    [
                        "inspect",
                        *self.identity,
                        "runs",
                        "--limit",
                        value,
                    ]
                )

    def test_batch_cli_requires_a_human_solving_prompt(self) -> None:
        status, _, errors = self.run_cli(
            ["add-challenge", *self.identity]
        )
        self.assertEqual(status, 0, errors)
        for command in (
            ["run-challenge", *self.identity, "--max-cycles", "1"],
            ["wave", *self.identity, "discovery"],
        ):
            with self.subTest(command=command[0]):
                status, _, errors = self.run_cli(command)
                self.assertNotEqual(status, 0)
                self.assertIn("problem-solving prompt", errors)

    def test_solve_announces_session_only_after_preparation_callback(self) -> None:
        self.add()

        def launch(*args, **kwargs):
            kwargs["on_prepared"](object())
            return 0

        with patch(
            "ctf_os.engine.challenge.ChallengeEngine.launch_live",
            side_effect=launch,
        ) as launch:
            status, output, errors = self.run_cli(
                ["solve", *self.identity]
            )
        self.assertEqual(status, 0, errors)
        self.assertIn("세 논리 역할", output)
        launch.assert_called_once()

    def test_thin_solve_selects_one_model_scaffold(self) -> None:
        self.add()

        def launch(*args, **kwargs):
            kwargs["on_prepared"](object())
            return 0

        with patch(
            "ctf_os.engine.challenge.ChallengeEngine.launch_live",
            side_effect=launch,
        ) as launch_mock:
            status, output, errors = self.run_cli(
                ["solve", *self.identity, "--mode", "thin"]
            )
        self.assertEqual(status, 0, errors)
        self.assertIn("frontier model 1개", output)
        self.assertEqual(
            launch_mock.call_args.kwargs["scaffold"],
            "thin_scaffold",
        )

    def test_competing_session_commands_do_not_replace_prompt_before_lock(
        self,
    ) -> None:
        self.add()
        identity = ChallengeIdentity(*self.identity)
        store = StateStore(self.root)
        paths = store.challenge_paths(identity)
        before = store.load(identity)
        canonical = paths.state.read_bytes()

        commands = (
            [
                "solve",
                *self.identity,
                "racing live prompt must not commit",
            ],
            [
                "run-challenge",
                *self.identity,
                "--prompt",
                "racing batch prompt must not commit",
                "--max-cycles",
                "1",
            ],
            [
                "add-challenge",
                *self.identity,
                "--prompt",
                "racing add prompt must not commit",
            ],
        )
        with ChallengeLock(
            paths.runtime / "session.lock",
            timeout=0,
        ) as session_lock:
            session_lock.acquire()
            for command in commands:
                with self.subTest(command=command[0]):
                    status, _, errors = self.run_cli(command)
                    self.assertNotEqual(status, 0)
                    self.assertIn("session", errors.lower())
        after = store.load(identity)
        self.assertEqual(after.prompt, before.prompt)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(paths.state.read_bytes(), canonical)

    def test_agent_flag_prints_immediately_and_never_submits(self) -> None:
        self.add()
        status, output, errors = self.run_cli(
            [
                "agent",
                "flag",
                "--contest",
                self.identity[0],
                "--category",
                self.identity[1],
                "--challenge",
                self.identity[2],
                "KCTF{candidate}",
            ]
        )
        self.assertEqual(status, 0)
        self.assertIn("candidate 기록", output)
        self.assertIn("FLAG CANDIDATE", errors)
        self.assertIn("미제출", errors)
        state = StateStore(self.root).load(
            ChallengeIdentity(*self.identity)
        )
        self.assertEqual(state.candidates[0].value, "KCTF{candidate}")
        self.assertEqual(state.submissions, [])

    def test_agent_goal_and_hypothesis_commands_use_typed_lifecycle(
        self,
    ) -> None:
        self.add()
        scope = [
            "--contest",
            self.identity[0],
            "--category",
            self.identity[1],
            "--challenge",
            self.identity[2],
        ]
        status, output, errors = self.run_cli(
            [
                "agent",
                "goal",
                *scope,
                "create",
                "--goal-id",
                "G-cli",
                "--description",
                "CLI goal",
                "--activate",
            ]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("status=active", output)
        status, output, errors = self.run_cli(
            [
                "agent",
                "hypothesis",
                *scope,
                "create",
                "--hypothesis-id",
                "H-cli",
                "--statement",
                "CLI hypothesis",
                "--falsifier",
                "run the opposite input",
                "--status",
                "open",
            ]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("status=open", output)
        state = StateStore(self.root).load(
            ChallengeIdentity(*self.identity)
        )
        self.assertIs(state.goals[-1].status, GoalStatus.ACTIVE)
        self.assertIs(
            state.hypotheses[-1].status,
            HypothesisStatus.OPEN,
        )

    def test_live_environment_root_and_duplicate_candidate_id(self) -> None:
        self.add()
        arguments = [
            "agent",
            "flag",
            "--contest",
            self.identity[0],
            "--category",
            self.identity[1],
            "--challenge",
            self.identity[2],
        ]
        session_directory = self.root / "session-cwd"
        session_directory.mkdir()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.dict(
                os.environ,
                {"CTFOS_WORKSPACE_ROOT": str(self.root)},
                clear=True,
            ),
            patch("pathlib.Path.cwd", return_value=session_directory),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main([*arguments, "KCTF{first}"], root=None)
        self.assertEqual(status, 0, stderr.getvalue())
        state = StateStore(self.root).load(
            ChallengeIdentity(*self.identity)
        )
        first_id = state.candidates[0].id

        self.run_cli([*arguments, "KCTF{second}"])
        status, duplicate_output, errors = self.run_cli(
            [*arguments, "KCTF{first}"]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn(first_id, duplicate_output)

    def test_manual_outcome_requires_proof_or_explicit_override(self) -> None:
        self.add()
        self.run_cli(
            [
                "agent",
                "flag",
                "--contest",
                self.identity[0],
                "--category",
                self.identity[1],
                "--challenge",
                self.identity[2],
                "KCTF{candidate}",
            ]
        )
        state = StateStore(self.root).load(
            ChallengeIdentity(*self.identity)
        )
        candidate_id = state.candidates[0].id
        status, _, errors = self.run_cli(
            [
                "submit",
                *self.identity,
                "--candidate",
                candidate_id,
                "--outcome",
                "rejected",
            ]
        )
        self.assertNotEqual(status, 0)
        self.assertIn("proof", errors)
        status, output, errors = self.run_cli(
            [
                "submit",
                *self.identity,
                "--candidate",
                candidate_id,
                "--outcome",
                "rejected",
                "--allow-unproved",
            ]
        )
        self.assertEqual(status, 0, errors)
        self.assertIn("사람 제출 결과", output)

    def test_init_config_is_idempotent(self) -> None:
        first, _, first_errors = self.run_cli(["init"])
        second, output, second_errors = self.run_cli(["init"])
        self.assertEqual(first, 0, first_errors)
        self.assertEqual(second, 0, second_errors)
        self.assertIn("이미 존재", output)

    def test_pin_image_updates_only_configured_digest_and_is_idempotent(
        self,
    ) -> None:
        status, _, errors = self.run_cli(["init"])
        self.assertEqual(status, 0, errors)
        config_path = self.root / ".ctfos" / "engine.toml"
        before = config_path.read_text(encoding="utf-8")
        with patch(
            "ctf_os.cli.inspect_local_image",
            return_value={
                "name": "ctf-os:core",
                "available": True,
                "id": IMAGE_DIGEST,
                "repo_digests": [],
            },
        ):
            status, output, errors = self.run_cli(["pin-image"])
            self.assertEqual(status, 0, errors)
            self.assertIn(IMAGE_DIGEST, output)
            first = config_path.read_text(encoding="utf-8")
            status, output, errors = self.run_cli(["pin-image"])
        self.assertEqual(status, 0, errors)
        self.assertIn("이미 고정됨", output)
        self.assertEqual(config_path.read_text(encoding="utf-8"), first)
        self.assertIn("# CTF-OS local engine configuration.", first)
        self.assertIn(f'image_digest = "{IMAGE_DIGEST}"', first)
        self.assertNotEqual(first, before)

    def test_pin_image_failure_leaves_config_unchanged(self) -> None:
        status, _, errors = self.run_cli(["init"])
        self.assertEqual(status, 0, errors)
        config_path = self.root / ".ctfos" / "engine.toml"
        before = config_path.read_bytes()
        with patch(
            "ctf_os.cli.inspect_local_image",
            return_value={
                "name": "ctf-os:core",
                "available": False,
                "error": "not found",
            },
        ):
            status, _, errors = self.run_cli(["pin-image"])
        self.assertNotEqual(status, 0)
        self.assertIn("고정할 수 없습니다", errors)
        self.assertEqual(config_path.read_bytes(), before)

    def test_pin_image_requires_initialized_config(self) -> None:
        status, _, errors = self.run_cli(["pin-image"])
        self.assertNotEqual(status, 0)
        self.assertIn("ctfos init", errors)

    def test_tool_rejects_background_start_before_sandbox(self) -> None:
        self.add()
        status, _, errors = self.run_cli(
            [
                "tool",
                "run",
                "--contest",
                self.identity[0],
                "--category",
                self.identity[1],
                "--challenge",
                self.identity[2],
                "--",
                "ctf-bg",
                "--",
                "sleep",
                "60",
            ]
        )
        self.assertNotEqual(status, 0)
        self.assertIn("background", errors)

    def test_session_scope_requires_token_and_rejects_cross_problem_jobs(self) -> None:
        self.add()
        session_environment = {
            "CTFOS_CONTEST": self.identity[0],
            "CTFOS_CATEGORY": self.identity[1],
            "CTFOS_CHALLENGE": self.identity[2],
        }
        with patch.dict(os.environ, session_environment, clear=True):
            status, _, errors = self.run_cli(
                [
                    "agent",
                    "flag",
                    "--contest",
                    self.identity[0],
                    "--category",
                    self.identity[1],
                    "--challenge",
                    self.identity[2],
                    "KCTF{must_not_record}",
                ]
            )
        self.assertNotEqual(status, 0)
        self.assertIn("capability", errors)

        other = ("국내 CTF", "web", "문제 2")
        status, _, errors = self.run_cli(
            ["add-challenge", *other, "--prompt", "web"]
        )
        self.assertEqual(status, 0, errors)
        engine = ChallengeEngine(self.root)
        state = engine.store.load(ChallengeIdentity(*self.identity))
        fingerprint = engine.sandbox(state).scope_fingerprint
        authority = CapabilityAuthority.from_file(
            engine.config.state_root / "runtime" / "capability-secret"
        )
        token = authority.issue(fingerprint)
        with patch.dict(
            os.environ,
            {
                **session_environment,
                "CTFOS_SCOPE_TOKEN": token,
            },
            clear=True,
        ):
            status, _, errors = self.run_cli(["jobs", *other])
        self.assertNotEqual(status, 0)
        self.assertIn("다른 문제 scope", errors)


if __name__ == "__main__":
    unittest.main()
