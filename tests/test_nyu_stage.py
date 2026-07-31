from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ctf_os import cli, nyu_stage as nyu_stage_module
from ctf_os.benchmark import BenchmarkExecutionFingerprint
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity
from ctf_os.nyu_stage import (
    MAX_CHALLENGE_JSON_BYTES,
    NYU_PUBLIC_METADATA_FILE,
    NYUStageError,
    stage_nyu_ctf_bench,
)
from ctf_os.promotion_bundles import (
    PromotionBundleError,
    freeze_promotion_manifest,
    prepare_promotion_session,
)
from ctf_os.store import StateAlreadyExists

CATEGORIES = ("pwn", "web", "rev", "crypto", "forensics", "misc")
FINGERPRINT = {
    "tool_manifest_sha256": "1" * 64,
    "image_sha256": "2" * 64,
    "model_config_sha256": "3" * 64,
    "engine_source_sha256": "4" * 64,
}


def _fingerprint_report(_workspace: Path) -> dict[str, object]:
    return {
        "schema_version": 2,
        "model_ids": ["gpt-5.6-sol"],
        "single_model": True,
        "execution_fingerprint": dict(FINGERPRINT),
        "engine_source_inventory": {},
    }


class NYUStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "nyu-source"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.case_ids = tuple(f"fixture-{category}" for category in CATEGORIES)
        self._build_source()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ("git", "-C", str(self.source), *arguments),
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _commit(self, message: str = "fixture") -> str:
        self._git("add", "--all")
        subprocess.run(
            (
                "git",
                "-c",
                "user.name=CTF-OS Tests",
                "-c",
                "user.email=ctfos-tests@example.invalid",
                "-C",
                str(self.source),
                "commit",
                "-q",
                "-m",
                message,
            ),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.commit = self._git("rev-parse", "HEAD")
        return self.commit

    def _build_source(self) -> None:
        self.source.mkdir()
        subprocess.run(
            ("git", "init", "-q", str(self.source)),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dataset: dict[str, object] = {}
        for category in CATEGORIES:
            case_id = f"fixture-{category}"
            name = f"public-{category}"
            relative = f"test/2026/CSAW-Quals/{category}/{name}"
            challenge = self.source / relative
            challenge.mkdir(parents=True)
            (challenge / "public.bin").write_bytes(
                f"public input for {category}\n".encode()
            )
            (challenge / "flag.txt").write_text(
                "flag{NEVER_COPY_THIS_VALUE}\n",
                encoding="utf-8",
            )
            (challenge / "writeup.md").write_text(
                "PRIVATE-WRITEUP-MARKER\n",
                encoding="utf-8",
            )
            (challenge / "solve.py").write_text(
                "PRIVATE-SOLVER-MARKER\n",
                encoding="utf-8",
            )
            (challenge / "challenge.json").write_text(
                json.dumps(
                    {
                        "name": name,
                        "category": category,
                        "description": f"Public description for {category}.",
                        "files": ["public.bin"],
                        "flag": "flag{NEVER_COPY_THIS_VALUE}",
                        "reference": "PRIVATE-REFERENCE-MARKER",
                        "writeup": "PRIVATE-WRITEUP-MARKER",
                        "solver": "PRIVATE-SOLVER-MARKER",
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            dataset[case_id] = {
                "year": "2026",
                "event": "CSAW-Quals",
                "category": category,
                "challenge": name,
                "path": relative,
            }
        (self.source / "test_dataset.json").write_text(
            json.dumps(dataset, sort_keys=True),
            encoding="utf-8",
        )
        self._commit()

    def _stage(
        self,
        *,
        workspace: Path | None = None,
        output: Path | None = None,
        commit: str | None = None,
        source: Path | None = None,
        split: str = "dev",
        case_ids: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, object], Path]:
        selected_workspace = workspace or self.workspace
        selected_output = output or selected_workspace / "nyu-partial.json"
        with mock.patch(
            "ctf_os.nyu_stage.execution_fingerprint_report",
            side_effect=_fingerprint_report,
        ):
            result = stage_nyu_ctf_bench(
                selected_workspace,
                source=source or self.source,
                release_commit=commit or self.commit,
                case_ids=case_ids or self.case_ids,
                output_manifest=selected_output,
                contest="nyu-fixture",
                split=split,
                wall_seconds=600,
                model_call_limit=12,
                total_token_limit=100_000,
            )
        return result, selected_output

    def test_cli_parser_exposes_explicit_nyu_stage_inputs(self) -> None:
        arguments = cli.build_parser().parse_args(
            [
                "benchmark",
                "nyu-stage",
                "--source",
                str(self.source),
                "--release-commit",
                self.commit,
                "--case",
                self.case_ids[0],
                "--output-manifest",
                "partial.json",
                "--contest",
                "nyu",
                "--split",
                "dev",
                "--wall-seconds",
                "600",
                "--model-call-limit",
                "12",
                "--total-token-limit",
                "100000",
            ]
        )

        self.assertEqual(arguments.benchmark_command, "nyu-stage")
        self.assertEqual(arguments.cases, [self.case_ids[0]])
        self.assertEqual(arguments.budget_wall_seconds, 600)

    def test_stages_six_fresh_sessions_per_case_without_private_fields(
        self,
    ) -> None:
        result, output = self._stage()

        self.assertTrue(result["staged"])
        self.assertEqual(result["cases"], 6)
        self.assertEqual(result["sessions"], 36)
        self.assertFalse(result["promotion_ready"])
        self.assertFalse(result["automatic_challenge_start"])
        self.assertFalse(result["model_visible_external_writeup_or_flag_access"])
        self.assertTrue(result["source_verifier_may_read_hidden_metadata"])
        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(manifest["metadata"]["partial_manifest"])
        self.assertFalse(manifest["metadata"]["promotion_ready"])
        self.assertTrue(
            manifest["metadata"]["source_verifier_may_read_hidden_metadata"]
        )
        self.assertEqual(
            set(manifest["metadata"]["emitted_public_metadata_fields"]),
            {
                "case_id",
                "category",
                "description",
                "files",
                "name",
                "path",
                "release_commit",
            },
        )
        for case in manifest["splits"][0]["cases"]:
            self.assertEqual(len(case["sessions"]), 6)
            incoming_digests = set()
            for session in case["sessions"]:
                incoming = (
                    self.workspace
                    / "incoming"
                    / "nyu-fixture"
                    / case["category"]
                    / session["challenge_id"]
                )
                self.assertEqual(
                    sorted(
                        item.relative_to(incoming).as_posix()
                        for item in incoming.rglob("*")
                        if item.is_file()
                    ),
                    [NYU_PUBLIC_METADATA_FILE, "public.bin"],
                )
                public_metadata = json.loads(
                    (incoming / NYU_PUBLIC_METADATA_FILE).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    set(public_metadata),
                    {
                        "case_id",
                        "category",
                        "description",
                        "files",
                        "name",
                        "path",
                        "release_commit",
                    },
                )
                self.assertEqual(public_metadata["case_id"], case["case_id"])
                self.assertEqual(public_metadata["category"], case["category"])
                self.assertEqual(public_metadata["files"], ["public.bin"])
                self.assertEqual(
                    public_metadata["release_commit"],
                    self.commit,
                )
                state = ChallengeEngine(self.workspace).store.load(
                    ChallengeIdentity(
                        "nyu-fixture",
                        case["category"],
                        session["challenge_id"],
                    )
                )
                self.assertEqual(state.budget.allocated_seconds, 600)
                self.assertEqual(state.budget.spent_seconds, 0)
                self.assertFalse(state.runs)
                incoming_digests.add(state.metadata["source_manifest_sha256"])
            self.assertEqual(incoming_digests, {case["input_manifest_sha256"]})
        staged_bytes = b"".join(
            path.read_bytes() for path in self.workspace.rglob("*") if path.is_file()
        )
        for private_value in (
            b"flag{NEVER_COPY_THIS_VALUE}",
            b"PRIVATE-REFERENCE-MARKER",
            b"PRIVATE-WRITEUP-MARKER",
            b"PRIVATE-SOLVER-MARKER",
        ):
            self.assertNotIn(private_value, staged_bytes)
        for arm, expected_mode in (
            ("thin_scaffold", "thin"),
            ("ctf_os", "managed"),
        ):
            step = next(
                item
                for item in result["session_next_steps"]
                if f"-{arm}-" in item["session_id"]
            )
            parsed = cli.build_parser().parse_args(
                shlex.split(step["operator_run"])[1:]
            )
            self.assertEqual(parsed.command, "solve")
            self.assertEqual(parsed.mode, expected_mode)

    def test_session_manifest_is_deterministic(self) -> None:
        _first_result, first_output = self._stage()
        second_workspace = self.root / "workspace-two"
        second_workspace.mkdir()
        _second_result, second_output = self._stage(
            workspace=second_workspace,
            output=second_workspace / "nyu-partial.json",
        )

        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())

    def test_regression_partial_does_not_fabricate_prior_exposure(self) -> None:
        regression_workspace = self.root / "regression-workspace"
        regression_workspace.mkdir()
        _result, output = self._stage(
            workspace=regression_workspace,
            output=regression_workspace / "regression.partial.json",
            split="regression",
        )

        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(manifest["splits"][0]["prior_engine_runs"], 0)
        self.assertFalse(manifest["metadata"]["promotion_ready"])

    def test_official_public_name_format_variants_are_accepted(self) -> None:
        variants = {
            "pwn": ("perfect_secrecy", "Perfect Secrecy"),
            "web": ("simple-recovery", "simple_recovery"),
            "rev": ("ransomware", "ransomwaRE"),
        }
        dataset_path = self.source / "test_dataset.json"
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        for category, (dataset_name, public_name) in variants.items():
            dataset[f"fixture-{category}"]["challenge"] = dataset_name
            challenge_json = self.source / (
                f"test/2026/CSAW-Quals/{category}/public-{category}/challenge.json"
            )
            document = json.loads(challenge_json.read_text(encoding="utf-8"))
            document["name"] = public_name
            challenge_json.write_text(
                json.dumps(document, sort_keys=True),
                encoding="utf-8",
            )
        dataset_path.write_text(
            json.dumps(dataset, sort_keys=True),
            encoding="utf-8",
        )
        variant_commit = self._commit("official name formatting variants")
        variant_workspace = self.root / "name-variant-workspace"
        variant_workspace.mkdir()
        _result, output = self._stage(
            workspace=variant_workspace,
            output=variant_workspace / "variants.partial.json",
            commit=variant_commit,
        )

        manifest = json.loads(output.read_text(encoding="utf-8"))
        cases = {case["category"]: case for case in manifest["splits"][0]["cases"]}
        for category, (_dataset_name, public_name) in variants.items():
            session = cases[category]["sessions"][0]
            public_metadata = json.loads(
                (
                    variant_workspace
                    / "incoming"
                    / "nyu-fixture"
                    / category
                    / session["challenge_id"]
                    / NYU_PUBLIC_METADATA_FILE
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(public_metadata["name"], public_name)

    def test_service_only_cases_get_distinct_public_metadata_digests(
        self,
    ) -> None:
        for category in ("pwn", "web"):
            challenge_json = self.source / (
                f"test/2026/CSAW-Quals/{category}/public-{category}/challenge.json"
            )
            document = json.loads(challenge_json.read_text(encoding="utf-8"))
            document["files"] = []
            challenge_json.write_text(
                json.dumps(document, sort_keys=True),
                encoding="utf-8",
            )
        empty_commit = self._commit("service-only public inputs")
        empty_workspace = self.root / "service-only-workspace"
        empty_workspace.mkdir()
        _result, output = self._stage(
            workspace=empty_workspace,
            output=empty_workspace / "service-only.partial.json",
            commit=empty_commit,
        )

        manifest = json.loads(output.read_text(encoding="utf-8"))
        selected = {
            case["category"]: case
            for case in manifest["splits"][0]["cases"]
            if case["category"] in {"pwn", "web"}
        }
        self.assertNotEqual(
            selected["pwn"]["input_manifest_sha256"],
            selected["web"]["input_manifest_sha256"],
        )
        for category, case in selected.items():
            first = case["sessions"][0]
            incoming = (
                empty_workspace
                / "incoming"
                / "nyu-fixture"
                / category
                / first["challenge_id"]
            )
            self.assertEqual(
                [
                    item.relative_to(incoming).as_posix()
                    for item in incoming.rglob("*")
                    if item.is_file()
                ],
                [NYU_PUBLIC_METADATA_FILE],
            )
            public_metadata = json.loads(
                (incoming / NYU_PUBLIC_METADATA_FILE).read_text(encoding="utf-8")
            )
            self.assertEqual(public_metadata["files"], [])
            self.assertEqual(
                set(public_metadata),
                {
                    "case_id",
                    "category",
                    "description",
                    "files",
                    "name",
                    "path",
                    "release_commit",
                },
            )

    def test_declared_challenge_json_is_rejected_before_workspace_mutation(
        self,
    ) -> None:
        challenge_json = (
            self.source / "test/2026/CSAW-Quals/pwn/public-pwn/challenge.json"
        )
        document = json.loads(challenge_json.read_text(encoding="utf-8"))
        document["files"] = ["public.bin", "challenge.json"]
        challenge_json.write_text(
            json.dumps(document, sort_keys=True),
            encoding="utf-8",
        )
        reserved_commit = self._commit("declare reserved metadata as public input")
        reserved_workspace = self.root / "reserved-workspace"
        reserved_workspace.mkdir()
        output = reserved_workspace / "partial.json"

        with self.assertRaisesRegex(NYUStageError, "challenge.json"):
            self._stage(
                workspace=reserved_workspace,
                output=output,
                commit=reserved_commit,
            )

        self.assertFalse(output.exists())
        self.assertFalse((reserved_workspace / "incoming").exists())
        self.assertFalse((reserved_workspace / ".ctfos").exists())
        self.assertEqual(list(reserved_workspace.iterdir()), [])

    def test_skip_worktree_asset_must_match_the_release_commit_blob(self) -> None:
        relative = "test/2026/CSAW-Quals/pwn/public-pwn/public.bin"
        self._git("update-index", "--skip-worktree", relative)
        asset = self.source / relative
        asset.write_bytes(b"locally substituted public input\n")
        self.assertEqual(self._git("status", "--porcelain"), "")
        mismatch_workspace = self.root / "blob-mismatch-workspace"
        mismatch_workspace.mkdir()
        output = mismatch_workspace / "partial.json"

        with self.assertRaisesRegex(
            NYUStageError,
            "(?:commit|blob|release)",
        ):
            self._stage(
                workspace=mismatch_workspace,
                output=output,
            )

        self.assertFalse(output.exists())
        self.assertFalse((mismatch_workspace / "incoming").exists())
        self.assertFalse((mismatch_workspace / ".ctfos").exists())
        self.assertEqual(list(mismatch_workspace.iterdir()), [])

    def test_repository_local_git_filters_are_rejected_before_staging(
        self,
    ) -> None:
        self._git("config", "--local", "filter.untrusted.clean", "cat")
        filtered_workspace = self.root / "filtered-workspace"
        filtered_workspace.mkdir()

        with self.assertRaisesRegex(
            NYUStageError,
            "filters or includes",
        ):
            self._stage(
                workspace=filtered_workspace,
                output=filtered_workspace / "partial.json",
            )

        self.assertEqual(list(filtered_workspace.iterdir()), [])

    def test_destination_state_race_uses_create_only_and_preserves_state(
        self,
    ) -> None:
        original_add = ChallengeEngine.add_challenge
        injected: list[
            tuple[ChallengeEngine, ChallengeIdentity, dict[str, object]]
        ] = []
        observed_exist_ok: list[object] = []

        def add_after_competing_create(
            engine: ChallengeEngine,
            identity: ChallengeIdentity,
            **kwargs: object,
        ) -> object:
            observed_exist_ok.append(kwargs.get("exist_ok"))
            if not injected:
                sentinel = engine.store.create_challenge(
                    identity,
                    description="competing operator state",
                    prompt="competing operator prompt",
                    exist_ok=False,
                )
                injected.append((engine, identity, sentinel.to_dict()))
            return original_add(engine, identity, **kwargs)

        with mock.patch.object(
            ChallengeEngine,
            "add_challenge",
            autospec=True,
            side_effect=add_after_competing_create,
        ):
            with self.assertRaises(StateAlreadyExists):
                self._stage()

        self.assertTrue(injected)
        engine, identity, before = injected[0]
        after = engine.store.load(identity).to_dict()
        self.assertEqual(after, before)
        self.assertTrue(observed_exist_ok)
        self.assertEqual(set(observed_exist_ok), {False})
        self.assertFalse((self.workspace / "nyu-partial.json").exists())

    def test_split_partials_share_one_release_benchmark_id(self) -> None:
        _dev_result, dev_output = self._stage()
        blind_workspace = self.root / "blind-workspace"
        blind_workspace.mkdir()
        _blind_result, blind_output = self._stage(
            workspace=blind_workspace,
            output=blind_workspace / "blind.partial.json",
            split="blind",
        )

        dev = json.loads(dev_output.read_text(encoding="utf-8"))
        blind = json.loads(blind_output.read_text(encoding="utf-8"))
        self.assertEqual(dev["benchmark_id"], blind["benchmark_id"])
        self.assertNotIn("-dev", dev["benchmark_id"])
        self.assertNotIn("-blind", blind["benchmark_id"])

    def test_mismatch_dirty_head_and_existing_outputs_fail_closed(self) -> None:
        wrong_head = "0" * len(self.commit)
        with self.assertRaisesRegex(NYUStageError, "HEAD"):
            self._stage(commit=wrong_head)

        (self.source / "test_dataset.json").write_text(
            (self.source / "test_dataset.json").read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(NYUStageError, "changes"):
            self._stage()
        self._git("checkout", "--", "test_dataset.json")

        output = self.workspace / "exists.json"
        output.write_text("owned by operator\n", encoding="utf-8")
        with self.assertRaisesRegex(NYUStageError, "already exists"):
            self._stage(output=output)
        self.assertEqual(
            output.read_text(encoding="utf-8"),
            "owned by operator\n",
        )

        challenge_json = (
            self.source / "test/2026/CSAW-Quals/pwn/public-pwn/challenge.json"
        )
        document = json.loads(challenge_json.read_text(encoding="utf-8"))
        document["category"] = "web"
        challenge_json.write_text(
            json.dumps(document, sort_keys=True),
            encoding="utf-8",
        )
        mismatch_commit = self._commit("metadata mismatch")
        mismatch_workspace = self.root / "mismatch-workspace"
        mismatch_workspace.mkdir()
        with self.assertRaisesRegex(NYUStageError, "mismatch"):
            self._stage(
                workspace=mismatch_workspace,
                output=mismatch_workspace / "partial.json",
                commit=mismatch_commit,
            )
        self.assertFalse((mismatch_workspace / "incoming").exists())
        self.assertFalse((mismatch_workspace / ".ctfos").exists())

    def test_git_query_bounds_both_streams_and_timeout(self) -> None:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_git = fake_bin / "git"
        fake_git.write_text(
            (
                f"#!{sys.executable}\n"
                "import os\n"
                "import sys\n"
                "import time\n"
                "mode = sys.argv[-1]\n"
                "if mode == 'stdout':\n"
                "    os.write(1, b'x' * 2048)\n"
                "elif mode == 'stderr':\n"
                "    os.write(2, b'x' * 2048)\n"
                "time.sleep(60)\n"
            ),
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        environment = {
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                nyu_stage_module,
                "MAX_GIT_OUTPUT_BYTES",
                1024,
            ),
        ):
            for mode in ("stdout", "stderr"):
                with mock.patch.object(
                    nyu_stage_module,
                    "GIT_QUERY_TIMEOUT_SECONDS",
                    5.0,
                ):
                    started = time.monotonic()
                    with self.subTest(mode=mode), self.assertRaises(
                        NYUStageError
                    ):
                        nyu_stage_module._git_query(
                            self.source,
                            mode,
                            label=f"synthetic Git {mode}",
                        )
                    self.assertLess(time.monotonic() - started, 2)

            started = time.monotonic()
            with (
                self.subTest(mode="timeout"),
                self.assertRaises(NYUStageError),
                mock.patch.object(
                    nyu_stage_module,
                    "GIT_QUERY_TIMEOUT_SECONDS",
                    0.2,
                ),
            ):
                nyu_stage_module._git_query(
                    self.source,
                    "timeout",
                    label="synthetic Git timeout",
                )
            self.assertLess(time.monotonic() - started, 2)

    def test_existing_state_is_rejected_before_any_new_session(self) -> None:
        engine = ChallengeEngine(self.workspace)
        existing_id = "nyu-dev-fixture-pwn-thin_scaffold-1"
        existing = ChallengeIdentity("nyu-fixture", "pwn", existing_id)
        engine.store.challenge_paths(existing).root.mkdir(parents=True)

        with self.assertRaisesRegex(NYUStageError, "state session"):
            self._stage()

        self.assertFalse((self.workspace / "nyu-partial.json").exists())
        self.assertFalse((self.workspace / "incoming" / "nyu-fixture" / "web").exists())

    def test_missing_category_and_oversized_metadata_are_rejected(self) -> None:
        with self.assertRaisesRegex(NYUStageError, "missing"):
            self._stage(case_ids=self.case_ids[:-1])
        self.assertFalse((self.workspace / "incoming").exists())

        challenge_json = (
            self.source / "test/2026/CSAW-Quals/pwn/public-pwn/challenge.json"
        )
        challenge_json.write_bytes(b" " * (MAX_CHALLENGE_JSON_BYTES + 1))
        oversized_commit = self._commit("oversized challenge metadata")
        oversized_workspace = self.root / "oversized-workspace"
        oversized_workspace.mkdir()
        with self.assertRaisesRegex(NYUStageError, "exceeds"):
            self._stage(
                workspace=oversized_workspace,
                output=oversized_workspace / "partial.json",
                commit=oversized_commit,
            )
        self.assertFalse((oversized_workspace / "incoming").exists())

    def test_source_and_input_symlinks_and_path_escape_are_rejected(
        self,
    ) -> None:
        source_link = self.root / "source-link"
        source_link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(NYUStageError, "symlink"):
            self._stage(source=source_link)

        public_file = self.source / "test/2026/CSAW-Quals/pwn/public-pwn/public.bin"
        public_file.unlink()
        public_file.symlink_to("flag.txt")
        symlink_commit = self._commit("symlink input")
        symlink_workspace = self.root / "symlink-workspace"
        symlink_workspace.mkdir()
        with self.assertRaisesRegex(NYUStageError, "regular files"):
            self._stage(
                workspace=symlink_workspace,
                output=symlink_workspace / "partial.json",
                commit=symlink_commit,
            )

        public_file.unlink()
        public_file.write_bytes(b"restored public input\n")
        dataset_path = self.source / "test_dataset.json"
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        dataset["fixture-pwn"]["path"] = "../outside"
        dataset_path.write_text(
            json.dumps(dataset, sort_keys=True),
            encoding="utf-8",
        )
        escape_commit = self._commit("path escape")
        escape_workspace = self.root / "escape-workspace"
        escape_workspace.mkdir()
        with self.assertRaisesRegex(NYUStageError, "normalized relative path"):
            self._stage(
                workspace=escape_workspace,
                output=escape_workspace / "partial.json",
                commit=escape_commit,
            )

    def test_partial_freeze_is_rejected_and_budget_reset_remains_preparable(
        self,
    ) -> None:
        _result, partial_path = self._stage()
        frozen_partial = self.workspace / "partial.frozen.json"
        with self.assertRaises(PromotionBundleError):
            freeze_promotion_manifest(
                self.workspace,
                partial_path,
                frozen_partial,
            )
        self.assertFalse(frozen_partial.exists())

        partial = json.loads(partial_path.read_text(encoding="utf-8"))
        complete = copy.deepcopy(partial)
        complete.pop("metadata")
        for split in ("regression", "blind", "live"):
            digest = hashlib.sha256(split.encode()).hexdigest()
            sessions = [
                {
                    "session_id": f"dummy-{split}-{arm}-{attempt}",
                    "arm": arm,
                    "attempt": attempt,
                    "contest_id": "nyu-fixture",
                    "category": "pwn",
                    "challenge_id": f"dummy-{split}-{arm}-{attempt}",
                }
                for arm in ("thin_scaffold", "ctf_os")
                for attempt in (1, 2, 3)
            ]
            complete["splits"].append(
                {
                    "name": split,
                    "trajectory_visible": False,
                    "answers_visible": False,
                    "prior_engine_runs": 1 if split == "regression" else 0,
                    "cases": [
                        {
                            "case_id": f"dummy-{split}",
                            "category": "pwn",
                            "input_manifest_sha256": digest,
                            "sessions": sessions,
                        }
                    ],
                }
            )
        complete_path = self.workspace / "complete.json"
        complete_path.write_text(
            json.dumps(complete, sort_keys=True),
            encoding="utf-8",
        )
        target_case = next(
            case for case in complete["splits"][0]["cases"] if case["category"] == "pwn"
        )
        target_session = target_case["sessions"][0]
        identity = ChallengeIdentity(
            target_session["contest_id"],
            target_session["category"],
            target_session["challenge_id"],
        )
        engine = ChallengeEngine(self.workspace)

        frozen_complete = self.workspace / "complete.frozen.json"
        typed_fingerprint = BenchmarkExecutionFingerprint(**FINGERPRINT)
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=typed_fingerprint,
        ):
            freeze_promotion_manifest(
                self.workspace,
                complete_path,
                frozen_complete,
            )
            reset = engine.reset_budget(identity, 600)
            self.assertEqual(reset.budget.spent_seconds, 0)
            self.assertFalse(reset.runs)
            prepared = prepare_promotion_session(
                self.workspace,
                frozen_complete,
                session_id=target_session["session_id"],
            )
        self.assertTrue(prepared["prepared"])
        self.assertFalse(prepared["automatic_challenge_start"])


if __name__ == "__main__":
    unittest.main()
