from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from ctf_os import cli
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.rev_runtime_proof import RevRuntimeProofError
from ctf_os.live_broker import MAX_INSPECT_PAGE_ITEMS
from ctf_os.models import ChallengeIdentity, GoalStatus, HypothesisStatus
from ctf_os.sandbox.daemon import CapabilityAuthority
from ctf_os.store import ChallengeLock, StateStore

IMAGE_DIGEST = "sha256:" + "a" * 64


def _rev_runtime_oracle() -> dict[str, object]:
    empty = hashlib.sha256(b"").hexdigest()

    def expectation(
        exit_code: int,
        stdout_sha256: str,
    ) -> dict[str, object]:
        return {
            "exit_code": exit_code,
            "stderr_sha256": empty,
            "stderr_size_bytes": 0,
            "stdout_sha256": stdout_sha256,
            "stdout_size_bytes": 8,
        }

    return {
        "accepted": expectation(0, "1" * 64),
        "controls": [
            {
                "expectation": expectation(7, digest * 64),
                "mutation_id": mutation_id,
            }
            for mutation_id, digest in (
                ("xor-first-01", "2"),
                ("xor-last-80", "3"),
                ("truncate-last", "4"),
            )
        ],
    }


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


class CLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.operator_directory = tempfile.TemporaryDirectory(
            prefix="ctfos-cli-operator-private-"
        )
        self.root = Path(self.temporary_directory.name)
        self.operator_input = (
            Path(self.operator_directory.name) / "accepted-input.bin"
        )
        self.operator_input.write_bytes(b"operator-private-input")
        self.operator_input.chmod(0o600)
        self.identity = ("국내 CTF", "rev", "문제 1")

    def tearDown(self) -> None:
        self.operator_directory.cleanup()
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

    def write_storage_config(self) -> None:
        directory = self.root / ".ctfos"
        directory.mkdir(exist_ok=True)
        (directory / "engine.toml").write_text(
            "[runtime]\n"
            "challenge_storage_quota_bytes = 111\n"
            "storage_scan_max_entries = 222\n"
            "storage_scan_max_bytes = 333\n",
            encoding="utf-8",
        )

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

    def test_contest_check_and_diagnose_are_snapshot_only_and_commands_parse(
        self,
    ) -> None:
        self.add()
        paths = StateStore(self.root).challenge_paths(
            ChallengeIdentity(*self.identity)
        )
        before = (
            paths.state.read_bytes(),
            paths.previous_state.read_bytes(),
            paths.events.read_bytes(),
        )
        doctor = {
            "ok": True,
            "warnings": [],
            "image": {"pin_status": "matched"},
            "managed_capabilities": {"status": "ready"},
        }
        with (
            patch("ctf_os.cli.collect_diagnostics", return_value=doctor),
            patch(
                "ctf_os.store.files.os.fchmod",
                side_effect=AssertionError("read-only open repaired permissions"),
            ),
            patch(
                "ctf_os.cli.ChallengeEngine",
                side_effect=AssertionError("read-only command built engine"),
            ),
        ):
            status, output, errors = self.run_cli(
                ["contest-check", self.identity[0], "--json"]
            )
        self.assertEqual(status, 0, errors)
        contest_report = json.loads(output)
        self.assertTrue(contest_report["ok"])
        self.assertEqual(contest_report["release"]["status"], "not_checked")

        with (
            patch(
                "ctf_os.store.files.os.fchmod",
                side_effect=AssertionError("read-only open repaired permissions"),
            ),
            patch(
                "ctf_os.cli.ChallengeEngine",
                side_effect=AssertionError("read-only command built engine"),
            ),
        ):
            status, output, errors = self.run_cli(
                ["diagnose", *self.identity, "--json"]
            )
        self.assertEqual(status, 0, errors)
        diagnosis = json.loads(output)
        parser = cli.build_parser()
        for command in diagnosis["next_commands"]:
            parser.parse_args(shlex.split(command)[1:])

        after = (
            paths.state.read_bytes(),
            paths.previous_state.read_bytes(),
            paths.events.read_bytes(),
        )
        self.assertEqual(before, after)

    def test_readiness_suggested_command_shapes_parse(self) -> None:
        parser = cli.build_parser()
        commands = (
            "ctfos preflight 'Demo CTF' web Example",
            "ctfos inspect 'Demo CTF' web Example summary",
            "ctfos inspect 'Demo CTF' web Example state",
            "ctfos inspect 'Demo CTF' web Example experiments",
            "ctfos inspect 'Demo CTF' web Example runs",
            "ctfos budget-reset 'Demo CTF' web Example",
            "ctfos migrate check",
            "ctfos target list 'Demo CTF' web Example",
            "ctfos target check 'Demo CTF' web Example T-1",
            (
                "ctfos target smoke 'Demo CTF' web Example T-1 "
                "--mode dns --mode tcp"
            ),
            "ctfos jobs 'Demo CTF' web Example --recover",
        )
        for command in commands:
            parser.parse_args(shlex.split(command)[1:])

    def test_contest_check_refuses_doctor_false_without_state_write(self) -> None:
        self.add()
        paths = StateStore(self.root).challenge_paths(
            ChallengeIdentity(*self.identity)
        )
        before = paths.state.read_bytes()
        doctor = {
            "ok": False,
            "warnings": ["pinned image is unavailable"],
            "image": {"pin_status": "missing"},
            "managed_capabilities": {"status": "blocked"},
        }
        with patch("ctf_os.cli.collect_diagnostics", return_value=doctor):
            status, output, errors = self.run_cli(
                ["contest-check", self.identity[0], "--json"]
            )
        self.assertEqual(status, 2, errors)
        report = json.loads(output)
        self.assertFalse(report["ok"])
        self.assertIn(
            "doctor_not_ready",
            {item["code"] for item in report["blockers"]},
        )
        self.assertEqual(before, paths.state.read_bytes())

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

    def test_rev_runtime_proof_forwards_only_data_and_prints_summary(
        self,
    ) -> None:
        oracle = _rev_runtime_oracle()
        oracle_path = self.root / "operator-oracle.json"
        oracle_path.write_bytes(_canonical_json_bytes(oracle))
        authorities = {
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "challenge_status_transition_authorized": False,
            "flag_proven": False,
        }
        result = {
            "authorities": authorities,
            "passed": True,
            "reason_codes": [],
            "record_count": 6,
        }
        state = Mock(revision=41)
        with (
            patch(
                "ctf_os.cli.prove_rev_runtime_accepted_input",
                return_value=(state, result),
            ) as prove,
            patch.object(
                ChallengeEngine,
                "record_candidate",
            ) as candidate,
            patch.object(
                ChallengeEngine,
                "record_manual_submission",
            ) as submission,
        ):
            status, output, errors = self.run_cli(
                [
                    "rev-prove-runtime",
                    *self.identity,
                    "--runtime-spec",
                    "private/runtime.json",
                    "--accepted-input-file",
                    str(self.operator_input),
                    "--oracle",
                    str(oracle_path),
                    "--timeout",
                    "77",
                ]
            )
        self.assertEqual(status, 0, errors)
        prove.assert_called_once_with(
            unittest.mock.ANY,
            ChallengeIdentity(*self.identity),
            runtime_spec_locator="private/runtime.json",
            accepted_input_path=self.operator_input,
            expected_oracle=oracle,
            timeout_seconds=77,
        )
        candidate.assert_not_called()
        submission.assert_not_called()
        summary = json.loads(output)
        self.assertEqual(
            set(summary),
            {
                "authorities",
                "evaluation_sha256",
                "passed",
                "reason_codes",
                "run_count",
                "state_revision",
            },
        )
        self.assertEqual(summary["authorities"], authorities)
        self.assertTrue(summary["passed"])
        self.assertEqual(summary["run_count"], 6)
        self.assertEqual(summary["state_revision"], 41)
        self.assertNotIn("private/runtime.json", output)
        self.assertNotIn(str(self.operator_input), output)
        self.assertNotIn(str(oracle_path), output)

    def test_rev_runtime_proof_parser_rejects_unbounded_timeout(self) -> None:
        parser = cli.build_parser()
        for value in ("0", "-1", "3601", "1.5"):
            with (
                self.subTest(timeout=value),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args(
                    [
                        "rev-prove-runtime",
                        *self.identity,
                        "--runtime-spec",
                        "runtime.json",
                        "--accepted-input-file",
                        str(self.operator_input),
                        "--oracle",
                        "oracle.json",
                        "--timeout",
                        value,
                    ]
                )

    def test_rev_runtime_proof_rejects_raw_oracle_before_engine(
        self,
    ) -> None:
        secret = "OPEN-SECRET-MUST-NOT-LOG"
        oracle_path = self.root / "invalid-oracle.json"
        oracle_path.write_text(
            json.dumps(
                {
                    **_rev_runtime_oracle(),
                    "accepted_input": secret,
                }
            ),
            encoding="utf-8",
        )
        with patch(
            "ctf_os.cli.prove_rev_runtime_accepted_input",
        ) as prove:
            status, output, errors = self.run_cli(
                [
                    "rev-prove-runtime",
                    *self.identity,
                    "--runtime-spec",
                    "runtime.json",
                    "--accepted-input-file",
                    str(self.operator_input),
                    "--oracle",
                    str(oracle_path),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertNotIn(secret, errors)
        prove.assert_not_called()

    def test_rev_runtime_duplicate_oracle_key_is_sanitized(self) -> None:
        secret = "EXPECTED_ORACLE_SECRET_7fbc"
        oracle_path = self.root / "duplicate-oracle.json"
        oracle_path.write_text(
            '{"' + secret + '":1,"' + secret + '":2}\n',
            encoding="utf-8",
        )
        with patch(
            "ctf_os.cli.prove_rev_runtime_accepted_input",
        ) as prove:
            status, output, errors = self.run_cli(
                [
                    "rev-prove-runtime",
                    *self.identity,
                    "--runtime-spec",
                    "runtime.json",
                    "--accepted-input-file",
                    str(self.operator_input),
                    "--oracle",
                    str(oracle_path),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertNotIn(secret, errors)
        self.assertIn("유효하지 않습니다", errors)
        prove.assert_not_called()

    def test_rev_runtime_engine_error_is_generic_and_sanitized(self) -> None:
        oracle = _rev_runtime_oracle()
        oracle_path = self.root / "operator-oracle.json"
        oracle_path.write_bytes(_canonical_json_bytes(oracle))
        secret = "PRIVATE_RUNTIME_ERROR_SECRET"
        with patch(
            "ctf_os.cli.prove_rev_runtime_accepted_input",
            side_effect=RevRuntimeProofError(secret),
        ):
            status, output, errors = self.run_cli(
                [
                    "rev-prove-runtime",
                    *self.identity,
                    "--runtime-spec",
                    "runtime.json",
                    "--accepted-input-file",
                    str(self.operator_input),
                    "--oracle",
                    str(oracle_path),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertNotIn(secret, errors)
        self.assertEqual(
            errors,
            "오류: Rev runtime proof를 안전하게 완료하지 못했습니다.\n",
        )

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

    def test_storage_inventory_and_plan_use_runtime_bounds(self) -> None:
        self.write_storage_config()
        self.add()
        identity = ChallengeIdentity(*self.identity)

        with patch(
            "ctf_os.cli.storage_inventory",
            return_value={"kind": "inventory"},
        ) as inventory:
            status, output, errors = self.run_cli(
                ["storage", "inventory", *self.identity]
            )
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output), {"kind": "inventory"})
        self.assertEqual(inventory.call_args.args[1], identity)
        self.assertEqual(
            inventory.call_args.kwargs,
            {
                "quota_bytes": 111,
                "max_entries": 222,
                "max_scan_bytes": 333,
            },
        )

        with patch(
            "ctf_os.cli.storage_plan",
            return_value={"kind": "plan"},
        ) as plan:
            status, output, errors = self.run_cli(
                ["storage", "plan", *self.identity]
            )
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output), {"kind": "plan"})
        self.assertEqual(plan.call_args.args[1], identity)
        self.assertEqual(
            plan.call_args.kwargs,
            {
                "quota_bytes": 111,
                "max_entries": 222,
                "max_scan_bytes": 333,
            },
        )

    def test_top_level_gc_is_the_same_quarantine_only_operation(self) -> None:
        self.write_storage_config()
        self.add()
        report = {
            "quarantine_id": "Q-" + "1" * 32,
            "permanent_delete_enabled": False,
        }
        with (
            patch(
                "ctf_os.cli.quarantine_unreachable",
                return_value=report,
            ) as quarantine,
            patch("ctf_os.cli.purge_quarantine") as purge,
        ):
            top_status, top_output, top_errors = self.run_cli(
                ["gc", *self.identity]
            )
            nested_status, nested_output, nested_errors = self.run_cli(
                ["storage", "gc", *self.identity]
            )

        self.assertEqual(top_status, 0, top_errors)
        self.assertEqual(nested_status, 0, nested_errors)
        self.assertEqual(json.loads(top_output), json.loads(nested_output))
        self.assertEqual(quarantine.call_count, 2)
        for call in quarantine.call_args_list:
            self.assertEqual(
                call.kwargs,
                {"max_entries": 222, "max_scan_bytes": 333},
            )
        purge.assert_not_called()

    def test_storage_purge_requires_and_forwards_exact_confirmation(
        self,
    ) -> None:
        self.write_storage_config()
        self.add()
        quarantine_id = "Q-" + "2" * 32
        manifest_sha256 = "a" * 64
        confirmation = (
            f"PURGE {self.identity[1]}/{self.identity[2]} "
            f"{quarantine_id} {manifest_sha256}"
        )

        with patch(
            "ctf_os.cli.prepare_quarantine_purge",
            return_value={"confirmation": confirmation},
        ) as prepare:
            status, output, errors = self.run_cli(
                [
                    "storage",
                    "purge-prepare",
                    *self.identity,
                    quarantine_id,
                ]
            )
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output)["confirmation"], confirmation)
        self.assertEqual(
            prepare.call_args.kwargs,
            {"max_verify_bytes": 333},
        )

        with patch(
            "ctf_os.cli.purge_quarantine",
            return_value={"status": "purged"},
        ) as purge:
            status, output, errors = self.run_cli(
                [
                    "storage",
                    "purge",
                    *self.identity,
                    quarantine_id,
                    "--manifest-sha256",
                    manifest_sha256,
                    "--confirm",
                    confirmation,
                ]
            )
        self.assertEqual(status, 0, errors)
        self.assertEqual(json.loads(output), {"status": "purged"})
        self.assertEqual(
            purge.call_args.kwargs,
            {
                "manifest_sha256": manifest_sha256,
                "confirmation": confirmation,
            },
        )

        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(
                [
                    "storage",
                    "purge",
                    *self.identity,
                    quarantine_id,
                    "--manifest-sha256",
                    manifest_sha256,
                ]
            )

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
