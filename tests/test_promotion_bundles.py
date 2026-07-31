from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.codex import (
    BatchInvocation,
    BatchRunner,
    LIVE_THIN_SCAFFOLD,
    LiveCommandBuilder,
    LiveSession,
    ModelCatalog,
    ReasoningEffort,
    Role,
)
from ctf_os.config import (
    default_config_text,
    load_config,
    set_runtime_image_digest,
)
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.knowledge import KnowledgeStore
from ctf_os.managed_continuity import (
    THREAD_CONTINUITY_CONTRACT_VERSION,
    THREAD_CONTINUITY_RUN_KEY,
    THREAD_CONTINUITY_SESSION_KEY,
    build_run_audit,
    build_session_metadata,
    source_generation,
)
from ctf_os.models import (
    ArtifactReference,
    Budget,
    BudgetMode,
    Fact,
    Falsifier,
    Hypothesis,
    ManagedCycle,
    Provenance,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
)
from ctf_os.promotion_bundles import (
    PromotionBundleError,
    capture_promotion_session,
    finalize_promotion_session,
    evaluate_promotion_bundles,
    freeze_promotion_manifest,
    local_execution_fingerprint,
    parse_promotion_manifest,
    prepare_promotion_session,
)
from ctf_os.scaffold_binding import (
    build_scaffold_launch_binding,
    managed_command_contract_sha256,
    parse_scaffold_launch_record,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import StateStore, sha256_file
from ctf_os.store.atomic import (
    atomic_write_json,
    atomic_write_text,
)


CATEGORIES = ("pwn", "web", "rev", "crypto", "forensics", "misc")


def _later(timestamp: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return (
        (parsed + timedelta(seconds=seconds))
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _case_layout() -> dict[str, tuple[tuple[str, str], ...]]:
    return {
        "dev": (("dev-pwn", "pwn"),),
        "regression": (("regression-web", "web"),),
        "blind": tuple(
            (f"blind-{category}", category)
            for category in CATEGORIES
        ),
        "live": tuple(
            (f"live-{category}", category)
            for category in CATEGORIES
        ),
    }


def _manifest(
    fingerprint: dict[str, str] | None = None,
) -> dict[str, object]:
    splits: list[dict[str, object]] = []
    for split, cases in _case_layout().items():
        case_records: list[dict[str, object]] = []
        for case_id, category in cases:
            sessions: list[dict[str, object]] = []
            for arm in (THIN_SCAFFOLD, CTF_OS_SYSTEM):
                for attempt in (1, 2, 3):
                    session_id = f"{case_id}-{arm}-{attempt}"
                    sessions.append(
                        {
                            "session_id": session_id,
                            "arm": arm,
                            "attempt": attempt,
                            "contest_id": "bundle-bench",
                            "category": category,
                            "challenge_id": session_id,
                        }
                    )
            case_records.append(
                {
                    "case_id": case_id,
                    "category": category,
                    "input_manifest_sha256": hashlib.sha256(
                        case_id.encode("ascii")
                    ).hexdigest(),
                    "sessions": sessions,
                }
            )
        splits.append(
            {
                "name": split,
                "trajectory_visible": split == "dev",
                "answers_visible": False,
                "prior_engine_runs": 1 if split == "regression" else 0,
                "cases": case_records,
            }
        )
    return {
        "schema_version": 2,
        "benchmark_id": "paired-bundle-fixture",
        "model_id": "gpt-5.6-sol",
        "budget": {
            "wall_seconds": 60,
            "model_call_limit": 8,
            "total_token_limit": 100_000,
        },
        "execution_fingerprint": fingerprint
        or {
            "tool_manifest_sha256": "1" * 64,
            "image_sha256": "2" * 64,
            "model_config_sha256": "3" * 64,
            "engine_source_sha256": "4" * 64,
        },
        "splits": splits,
    }


class PromotionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.store = StateStore(self.root)
        self.manifest_path = self.root / "manifest.json"
        self.frozen_path = self.root / "manifest.frozen.json"
        self.source_root = self.root / "runtime-source"
        for relative, payload in {
            "ctf_os/__init__.py": b'"""fixture package."""\n',
            "ctf_os/__main__.py": b"from ctf_os.cli import main\n",
            "ctf_os/benchmark.py": b"SCHEMA = 3\n",
            "ctf_os/cli.py": b"def main(): return 0\n",
            "ctf_os/container_tools.py": b"def main(): return 0\n",
            "ctf_os/promotion_bundles.py": b"PROMOTION = 2\n",
            "ctf_os/runtime_source.py": b"INVENTORY = 1\n",
            "ctf_os/engine/core.py": b"ENGINE = 'clean'\n",
            "pyproject.toml": (
                b"[project]\nname='fixture'\nversion='1.0.0'\n"
            ),
        }.items():
            target = self.source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        subprocess.run(
            ("git", "init", "-q", str(self.source_root)),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ("git", "-C", str(self.source_root), "add", "--all"),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            (
                "git",
                "-c",
                "user.name=CTF-OS Tests",
                "-c",
                "user.email=ctfos-tests@example.invalid",
                "-C",
                str(self.source_root),
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "fixture",
            ),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.source_patch = mock.patch(
            "ctf_os.runtime_source._RUNTIME_SOURCE_ROOT",
            self.source_root,
        )
        self.source_patch.start()
        config_path = self.root / ".ctfos" / "engine.toml"
        atomic_write_text(
            config_path,
            set_runtime_image_digest(
                default_config_text(),
                "sha256:" + "2" * 64,
            ),
            mode=0o600,
        )
        fingerprint = local_execution_fingerprint(self.root)
        self.manifest = _manifest(
            {
                "tool_manifest_sha256": (
                    fingerprint.tool_manifest_sha256
                ),
                "image_sha256": fingerprint.image_sha256,
                "model_config_sha256": (
                    fingerprint.model_config_sha256
                ),
                "engine_source_sha256": (
                    fingerprint.engine_source_sha256
                ),
            }
        )
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.source_patch.stop()
        self.temporary_directory.cleanup()

    def _session_records(self) -> list[tuple[str, str, str, str, int]]:
        parsed = parse_promotion_manifest(self.manifest)
        return [
            (
                session.session_id,
                session.case_id,
                session.split,
                session.arm,
                session.attempt,
            )
            for session in sorted(
                parsed.sessions.values(),
                key=lambda value: value.session_id,
            )
        ]

    def _create_unprepared_state(
        self,
        session_id: str,
        *,
        prompt: str = "",
    ):
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[session_id]
        state = self.store.create_challenge(
            session.identity,
            prompt=prompt,
            metadata={
                "source_manifest_sha256": (
                    session.input_manifest_sha256
                ),
            },
            budget=Budget(
                allocated_seconds=60,
                spent_seconds=0,
                mode=BudgetMode.BOUNDED,
            ),
            schema_version=STATE_SCHEMA_VERSION,
            exist_ok=False,
        )
        return session, state

    def _create_state(
        self,
        session_id: str,
        case_id: str,
        split: str,
        arm: str,
        attempt: int,
        *,
        prompt: str = "",
    ) -> None:
        parsed = parse_promotion_manifest(self.manifest)
        session, state = self._create_unprepared_state(
            session_id,
            prompt=prompt,
        )
        # The generic proof fixture exercises the collector independently
        # from each category's current typed proof contract.  The scaffold
        # evidence itself is nevertheless canonical schema v2: arm labels
        # without typed execution bindings must never satisfy collection.
        original_created = datetime.fromisoformat(
            state.created_at.replace("Z", "+00:00")
        )

        state.created_at = (
            (original_created - timedelta(seconds=30))
            .astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        state.updated_at = state.created_at
        state.validate()
        paths = self.store.challenge_paths(session.identity)
        atomic_write_json(paths.state, state.to_dict(), mode=0o600)
        atomic_write_json(
            paths.previous_state,
            state.to_dict(),
            mode=0o600,
        )
        prepare_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session_id,
        )
        state = self.store.load(session.identity, recover=False)
        config = load_config(self.root)
        if arm == THIN_SCAFFOLD:
            command_contract_sha256 = LiveCommandBuilder(
                models=ModelCatalog(
                    sol=parsed.model_id,
                    terra=parsed.model_id,
                    luna=parsed.model_id,
                )
            ).command_contract_sha256(
                LiveSession(
                    session_key="promotion-thin-fixture",
                    working_directory=Path("/challenge"),
                    prompt="frozen thin evaluation",
                    model_id=parsed.model_id,
                    reasoning_effort=ReasoningEffort(
                        config.models.captain_effort
                    ),
                    logical_worker_roles=(),
                    scaffold=LIVE_THIN_SCAFFOLD,
                ),
                headless=True,
            )
        else:
            command_contract_sha256 = managed_command_contract_sha256(
                model_id=parsed.model_id,
                captain_effort=config.models.captain_effort,
                worker_effort=config.models.worker_effort,
                thread_continuity_policy="fresh",
            )
        launched = ChallengeEngine(
            self.root,
            config=config,
            store=self.store,
        ).record_evaluation_scaffold_launch(
            session.identity,
            arm=arm,
            command_contract_sha256=command_contract_sha256,
        )
        launch_binding, _launched_at = parse_scaffold_launch_record(
            launched.metadata["evaluation_scaffold_launch"]
        )
        state = launched
        seconds = (
            5
            if arm == CTF_OS_SYSTEM and split == "live"
            else 10
        )
        run_id = f"R-{session_id}"
        run_directory = Path("runs") / run_id
        run_paths = {
            "request_path": run_directory / "request.json",
            "result_path": run_directory / "result.json",
            "validation_path": run_directory / "validation.json",
        }
        challenge_root = self.store.challenge_paths(session.identity).root
        usage = {
            "input_tokens": 100,
            "cached_input_tokens": 0,
            "output_tokens": 50,
            "reasoning_output_tokens": 25,
        }
        request_path = challenge_root / run_paths["request_path"]
        request_path.parent.mkdir(parents=True, exist_ok=True)
        request_document: dict[str, object] = {
            "run_id": run_id,
            "session_id": session_id,
            "base_revision": state.revision,
        }
        evidence_artifacts: list[ArtifactReference] = []
        thin_extra: dict[str, object] = {}
        if arm == THIN_SCAFFOLD:
            request_document.update(
                {
                    "evaluation_scaffold": THIN_SCAFFOLD,
                    "execution_transport": "headless_jsonl",
                    "usage_attestation": "codex_jsonl_events",
                    "command_contract_sha256": (
                        command_contract_sha256
                    ),
                }
            )
            schema_relative = run_directory / "output-schema.json"
            jsonl_relative = (
                run_directory / "raw" / "attempt-1.jsonl"
            )
            stderr_relative = (
                run_directory / "raw" / "attempt-1.stderr"
            )
            output_relative = (
                run_directory / "attempt-1-output.json"
            )
            capture_relative = (
                run_directory / "raw" / "attempt-1-capture.json"
            )
            jsonl_text = "\n".join(
                (
                    json.dumps(
                        {
                            "type": "thread.started",
                            "thread_id": "fixture-thread",
                        },
                        sort_keys=True,
                    ),
                    json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": usage,
                        },
                        sort_keys=True,
                    ),
                    "",
                )
            )
            for relative, value in (
                (schema_relative, {"type": "object"}),
                (output_relative, {}),
            ):
                target = challenge_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_json(target, value, mode=0o400)
            jsonl_path = challenge_root / jsonl_relative
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(
                jsonl_path,
                jsonl_text,
                mode=0o400,
            )
            stderr_path = challenge_root / stderr_relative
            atomic_write_text(stderr_path, "", mode=0o400)
            output_path = challenge_root / output_relative
            capture_path = challenge_root / capture_relative
            atomic_write_json(
                capture_path,
                {
                    "schema_version": 1,
                    "stdout_jsonl": {
                        "limit_bytes": 1024 * 1024,
                        "bytes": jsonl_path.stat().st_size,
                        "stored_bytes": jsonl_path.stat().st_size,
                        "truncated": False,
                        "truncation_known": True,
                        "capture_complete": True,
                        "oversized_event_lines": 0,
                    },
                    "stderr": {
                        "limit_bytes": 1024 * 1024,
                        "bytes": 0,
                        "stored_bytes": 0,
                        "truncated": False,
                        "truncation_known": True,
                        "capture_complete": True,
                    },
                    "structured_output": {
                        "limit_bytes": 1024 * 1024,
                        "bytes": output_path.stat().st_size,
                        "oversized": False,
                    },
                    "event_accumulator": {
                        "event_limit": 10_000,
                        "events_stored": 2,
                        "events_dropped": 0,
                        "malformed_line_limit": 1_000,
                        "malformed_lines_stored": 0,
                        "malformed_lines_dropped": 0,
                    },
                    "flag_scan": {
                        "candidate_limit": 1_024,
                        "candidate_chars_limit": 256 * 1_024,
                        "candidates_stored": 0,
                        "candidate_chars_stored": 0,
                        "suppressed_matches": 0,
                    },
                },
                mode=0o400,
            )
            for index, (relative, media_type) in enumerate(
                (
                    (schema_relative, "application/schema+json"),
                    (jsonl_relative, "application/x-ndjson"),
                    (stderr_relative, "text/plain"),
                    (output_relative, "application/json"),
                    (capture_relative, "application/json"),
                ),
                start=1,
            ):
                target = challenge_root / relative
                evidence_artifacts.append(
                    ArtifactReference(
                        id=f"A-{run_id}-{index}",
                        path=relative.as_posix(),
                        sha256=sha256_file(target),
                        source_run_id=run_id,
                        media_type=media_type,
                        size=target.stat().st_size,
                    )
                )
            thread_digest = hashlib.sha256(
                b"fixture-thread"
            ).hexdigest()
            result_document: dict[str, object] = {
                "schema_version": 1,
                "base_revision": state.revision,
                "status": RunStatus.COMPLETED.value,
                "evaluation_scaffold": THIN_SCAFFOLD,
                "semantic_output_committed": False,
                "usage": usage,
                "usage_event_observed": True,
                "capture_complete": True,
                "thread_id_sha256": thread_digest,
                "evidence": [
                    {
                        "artifact_id": artifact.id,
                        "path": artifact.path,
                        "sha256": artifact.sha256,
                        "size_bytes": artifact.size,
                    }
                    for artifact in evidence_artifacts
                ],
                "automatic_submission": False,
            }
            validation_document: dict[str, object] = {
                "schema_version": 1,
                "base_revision": state.revision,
                "ok": True,
                "errors": [],
            }
            thin_extra = {
                "capture_complete": True,
                "attempt_count": 1,
                "produced_thread_id_sha256": thread_digest,
                "evidence_artifact_ids": [
                    artifact.id for artifact in evidence_artifacts
                ],
            }
        else:
            result_document = {
                "base_revision": state.revision,
                "status": RunStatus.COMPLETED.value,
                "provisional_managed_result": True,
                "attempt_output_path": None,
                "attempt_count": 1,
                "artifacts": [],
                "flag_candidate_count": 0,
                "failure_kinds": [],
            }
            validation_document = {
                "ok": True,
                "base_revision": state.revision,
                "errors": [],
                "provisional_managed_result": True,
            }
        atomic_write_json(
            request_path,
            request_document,
            mode=0o400,
        )
        atomic_write_json(
            challenge_root / run_paths["result_path"],
            result_document,
            mode=0o400,
        )
        atomic_write_json(
            challenge_root / run_paths["validation_path"],
            validation_document,
            mode=0o400,
        )
        run_file_bindings = {
            "attempt_count": 1,
            "request_sha256": sha256_file(request_path),
            "result_sha256": sha256_file(
                challenge_root / run_paths["result_path"]
            ),
            "validation_sha256": sha256_file(
                challenge_root / run_paths["validation_path"]
            ),
        }

        def mutate(current) -> None:
            current.budget.spent_seconds = 20
            run_extra: dict[str, object] = {
                "usage": usage,
                **run_file_bindings,
            }
            run_origin = RunOrigin.MANAGED_MODEL
            run_session_id = f"managed-{session_id}"
            cycle_id: str | None = f"cycle-{session_id}"
            if arm == THIN_SCAFFOLD:
                run_origin = RunOrigin.ASSISTED_MODEL
                run_session_id = session_id
                cycle_id = None
                run_extra.update(
                    {
                        "evaluation_scaffold": THIN_SCAFFOLD,
                        "execution_transport": "headless_jsonl",
                        "usage_attestation": "codex_jsonl_events",
                        "usage_attestation_valid": True,
                        "semantic_output_committed": False,
                        "logical_model_count": 1,
                        "logical_worker_roles": [],
                        "command_contract_sha256": (
                            command_contract_sha256
                        ),
                        "launch_binding_sha256": (
                            launch_binding.binding_sha256
                        ),
                        **thin_extra,
                    }
                )
            model_run = RunReference(
                id=run_id,
                base_revision=current.revision,
                status=RunStatus.COMPLETED,
                request_path=run_paths["request_path"].as_posix(),
                result_path=run_paths["result_path"].as_posix(),
                validation_path=run_paths[
                    "validation_path"
                ].as_posix(),
                role="captain",
                model="gpt-5.6-sol",
                origin=run_origin,
                session_id=run_session_id,
                cycle_id=cycle_id,
                configuration_epoch=current.configuration_epoch,
                extra=run_extra,
            )
            current.runs.append(model_run)
            current.artifacts.extend(evidence_artifacts)
            if arm == CTF_OS_SYSTEM:
                continuity = build_session_metadata(
                    policy="fresh",
                    configuration_epoch=current.configuration_epoch,
                    source_manifest_sha256=session.input_manifest_sha256,
                    source_generation=source_generation(
                        session.input_manifest_sha256,
                        current.metadata.get("source_manifest_history"),
                    ),
                    target_id=None,
                    target_generation=None,
                    runtime_image_digest=config.runtime.image_digest,
                    captain_effort=config.models.captain_effort,
                    worker_effort=config.models.worker_effort,
                    models={
                        role: getattr(config.models, role)
                        for role in (
                            "captain",
                            "recon",
                            "specialist",
                            "builder",
                            "falsifier",
                            "extractor",
                            "reproducer",
                            "validator",
                            "evidence_auditor",
                        )
                    },
                )
                run_extra["contract_version"] = (
                    THREAD_CONTINUITY_CONTRACT_VERSION
                )
                run_extra[THREAD_CONTINUITY_RUN_KEY] = build_run_audit(
                    session_metadata=continuity,
                    session_id=run_session_id,
                    role="captain",
                    model=parsed.model_id,
                    decision="fresh",
                    reason="policy_fresh",
                    source_run_id=None,
                    source_thread_id_sha256=None,
                    stable_lane=False,
                    lane_identity_sha256=None,
                    workspace_owner_run_id=None,
                )
                current.sessions.append(
                    SolveSession(
                        id=run_session_id,
                        mode=SessionMode.MANAGED,
                        status=SessionStatus.COMPLETED,
                        configuration_epoch=(
                            current.configuration_epoch
                        ),
                        start_revision=current.revision,
                        end_revision=current.revision,
                        run_ids=[run_id],
                        evaluation_policy="observe",
                        extra={
                            THREAD_CONTINUITY_SESSION_KEY: continuity,
                        },
                    )
                )
                current.cycles.append(
                    ManagedCycle(
                        id=cycle_id,
                        session_id=run_session_id,
                        ordinal=1,
                        phase="completed",
                        configuration_epoch=(
                            current.configuration_epoch
                        ),
                        captain_run_id=run_id,
                        completed_at=_later(current.created_at, seconds),
                    )
                )

        self.store.update(session.identity, mutate)
        finalize_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session_id,
            human_interventions=0,
            secret_or_flag_leaks=0,
        )

    def _freeze(self) -> None:
        freeze_promotion_manifest(
            self.root,
            self.manifest_path,
            self.frozen_path,
        )

    def _change_runtime_source_one_byte(self) -> tuple[Path, bytes]:
        source = self.source_root / "ctf_os" / "engine" / "core.py"
        original = source.read_bytes()
        changed = original.replace(b"clean", b"cleao")
        self.assertEqual(len(changed), len(original))
        self.assertNotEqual(changed, original)
        source.write_bytes(changed)
        return source, original

    def _commit_runtime_source_change(self) -> None:
        subprocess.run(
            (
                "git",
                "-C",
                str(self.source_root),
                "add",
                "ctf_os/engine/core.py",
            ),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            (
                "git",
                "-c",
                "user.name=CTF-OS Tests",
                "-c",
                "user.email=ctfos-tests@example.invalid",
                "-C",
                str(self.source_root),
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "change runtime source",
            ),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_dirty_source_rehash_relabel_fails_at_freeze(self) -> None:
        source, _original = self._change_runtime_source_one_byte()
        self.manifest["execution_fingerprint"][
            "engine_source_sha256"
        ] = hashlib.sha256(source.read_bytes()).hexdigest()
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "runtime source inventory",
        ):
            self._freeze()
        self.assertFalse(self.frozen_path.exists())

    def test_source_change_after_freeze_blocks_prepare(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._change_runtime_source_one_byte()
        with self.assertRaisesRegex(
            PromotionBundleError,
            "runtime source inventory",
        ):
            self._create_state(*record)

    def test_source_change_after_prepare_blocks_launch(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        state = self.store.create_challenge(
            session.identity,
            metadata={
                "source_manifest_sha256": (
                    session.input_manifest_sha256
                )
            },
            budget=Budget(
                allocated_seconds=60,
                spent_seconds=0,
                mode=BudgetMode.BOUNDED,
            ),
            schema_version=STATE_SCHEMA_VERSION,
            exist_ok=False,
        )
        prepare_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session.session_id,
        )
        self._change_runtime_source_one_byte()
        engine = ChallengeEngine(
            self.root,
            config=load_config(self.root),
            store=self.store,
        )
        with self.assertRaisesRegex(
            EngineError,
            "execution fingerprint",
        ):
            engine.record_evaluation_scaffold_launch(
                session.identity,
                arm=session.arm,
                command_contract_sha256="a" * 64,
            )
        current = self.store.load(session.identity, recover=False)
        self.assertEqual(current.revision, state.revision + 1)
        self.assertNotIn(
            "evaluation_scaffold_launch",
            current.metadata,
        )

    def test_source_change_after_launch_blocks_queued_provider(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        self._change_runtime_source_one_byte()

        class ProviderExecutor:
            calls = 0

            def run(self, command, *, cwd, timeout, on_stdout_line):
                del command, cwd, timeout, on_stdout_line
                self.calls += 1
                raise AssertionError("provider must not start")

        executor = ProviderExecutor()
        engine = ChallengeEngine(
            self.root,
            config=load_config(self.root),
            store=self.store,
            batch_runner=BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
            ),
        )
        result = engine.batch_runner.run(
            BatchInvocation(
                run_id="queued-source-change",
                role=Role.CAPTAIN,
                prompt="must not reach the provider",
                working_directory=self.root,
                output_directory=self.root / "queued-provider",
            ),
            before_provider_start=lambda: (
                engine._before_provider_start(
                    parse_promotion_manifest(
                        self.manifest
                    ).sessions[record[0]].identity
                )
            ),
        )
        self.assertEqual(executor.calls, 0)
        self.assertFalse(result.success)
        self.assertIn(
            "model_call_cancelled",
            {failure.kind for failure in result.failures},
        )

    def test_source_change_blocks_capture_and_bundle_verification(
        self,
    ) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        source, original = self._change_runtime_source_one_byte()
        with self.assertRaisesRegex(
            PromotionBundleError,
            "runtime source inventory",
        ):
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=self.root / "dirty-capture",
            )
        source.write_bytes(original)
        bundle = self.root / "clean-capture"
        capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=bundle,
        )
        self._change_runtime_source_one_byte()
        with self.assertRaisesRegex(
            PromotionBundleError,
            "runtime source inventory",
        ):
            evaluate_promotion_bundles(
                self.root,
                self.frozen_path,
                [bundle],
            )

    def test_validly_rehashed_source_launch_relabel_still_fails(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        config = load_config(self.root)
        self._change_runtime_source_one_byte()
        self._commit_runtime_source_change()
        relabelled = local_execution_fingerprint(
            self.root
        ).engine_source_sha256
        self.assertNotEqual(
            relabelled,
            parsed.fingerprint.engine_source_sha256,
        )

        def relabel(current) -> None:
            prior, _timestamp = parse_scaffold_launch_record(
                current.metadata["evaluation_scaffold_launch"]
            )
            current.metadata[
                "evaluation_engine_source_sha256"
            ] = relabelled
            current.metadata["evaluation_scaffold_launch"] = (
                build_scaffold_launch_binding(
                    metadata=current.metadata,
                    configuration_epoch=current.configuration_epoch,
                    contest_id=session.contest_id,
                    category=session.category,
                    challenge_id=session.challenge_id,
                    arm=session.arm,
                    model_id=parsed.model_id,
                    runtime_image_digest=config.runtime.image_digest,
                    command_contract_sha256=(
                        prior.command_contract_sha256
                    ),
                ).to_record()
            )

        self.store.update(session.identity, relabel)
        with self.assertRaisesRegex(
            PromotionBundleError,
            "execution fingerprint differs",
        ):
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=self.root / "source-relabel",
            )

    def test_exact_types_leakage_and_missing_attempts_fail_before_freeze(
        self,
    ) -> None:
        base = _manifest()
        mutations: dict[str, dict[str, object]] = {}

        schema_bool = copy.deepcopy(base)
        schema_bool["schema_version"] = True
        mutations["boolean schema version"] = schema_bool

        visibility_integer = copy.deepcopy(base)
        visibility_integer["splits"][2]["answers_visible"] = 0
        mutations["integer visibility"] = visibility_integer

        blind_answer = copy.deepcopy(base)
        blind_answer["splits"][2]["answers_visible"] = True
        mutations["blind answer visibility"] = blind_answer

        blind_trajectory = copy.deepcopy(base)
        blind_trajectory["splits"][2]["trajectory_visible"] = True
        mutations["blind trajectory visibility"] = blind_trajectory

        missing_attempt = copy.deepcopy(base)
        missing_attempt["splits"][0]["cases"][0]["sessions"].pop()
        mutations["missing attempt"] = missing_attempt

        attempt_bool = copy.deepcopy(base)
        attempt_bool["splits"][0]["cases"][0]["sessions"][0][
            "attempt"
        ] = True
        mutations["boolean attempt"] = attempt_bool

        missing_source = copy.deepcopy(base)
        del missing_source["execution_fingerprint"][
            "engine_source_sha256"
        ]
        mutations["missing engine source fingerprint"] = missing_source

        extra_source = copy.deepcopy(base)
        extra_source["execution_fingerprint"]["source_commit"] = "deadbeef"
        mutations["extra engine source fingerprint field"] = extra_source

        source_bool = copy.deepcopy(base)
        source_bool["execution_fingerprint"][
            "engine_source_sha256"
        ] = True
        mutations["boolean engine source fingerprint"] = source_bool

        for label, value in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(PromotionBundleError):
                    parse_promotion_manifest(value)

    def test_preloaded_trajectory_and_knowledge_fail_before_prepare(
        self,
    ) -> None:
        self._freeze()
        records = self._session_records()

        fact_session, _state = self._create_unprepared_state(
            records[0][0]
        )

        def inject_fact(current) -> None:
            current.facts.append(
                Fact(
                    id="F-preloaded-answer",
                    statement="preloaded public writeup answer",
                    provenance=Provenance.EXTERNAL_DOC,
                    challenge_id=current.challenge_id,
                )
            )

        self.store.update(fact_session.identity, inject_fact)
        with self.assertRaisesRegex(
            PromotionBundleError,
            "pre-run trajectory state",
        ):
            prepare_promotion_session(
                self.root,
                self.frozen_path,
                session_id=records[0][0],
            )

        hypothesis_session, _state = self._create_unprepared_state(
            records[1][0]
        )

        def inject_hypothesis(current) -> None:
            current.hypotheses.append(
                Hypothesis(
                    id="H-preloaded-answer",
                    statement="the public writeup already gives the answer",
                    falsifier=Falsifier(
                        description="must not enter a blind session"
                    ),
                )
            )

        self.store.update(
            hypothesis_session.identity,
            inject_hypothesis,
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "pre-run trajectory state",
        ):
            prepare_promotion_session(
                self.root,
                self.frozen_path,
                session_id=records[1][0],
            )

        artifact_session, _state = self._create_unprepared_state(
            records[2][0]
        )
        artifact_relative = Path("artifacts") / "preloaded-answer.txt"
        artifact_path = (
            self.store.challenge_paths(artifact_session.identity).root
            / artifact_relative
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text("preloaded answer artifact", encoding="utf-8")

        def inject_artifact(current) -> None:
            current.artifacts.append(
                ArtifactReference(
                    id="A-preloaded-answer",
                    path=artifact_relative.as_posix(),
                    sha256=sha256_file(artifact_path),
                    size=artifact_path.stat().st_size,
                    media_type="text/plain",
                )
            )

        self.store.update(artifact_session.identity, inject_artifact)
        with self.assertRaisesRegex(
            PromotionBundleError,
            "pre-run trajectory state",
        ):
            prepare_promotion_session(
                self.root,
                self.frozen_path,
                session_id=records[2][0],
            )

        knowledge_session, _state = self._create_unprepared_state(
            records[3][0]
        )
        writeup = self.root / "public-writeup.txt"
        writeup.write_text(
            "flag{must-not-enter-a-promotion-context}",
            encoding="utf-8",
        )
        KnowledgeStore(self.store).add(
            knowledge_session.identity,
            writeup,
            source_url="https://example.invalid/public-writeup",
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "empty challenge knowledge snapshot",
        ):
            prepare_promotion_session(
                self.root,
                self.frozen_path,
                session_id=records[3][0],
            )

    def test_real_initial_ingest_seeds_remain_preparable(self) -> None:
        parsed = parse_promotion_manifest(self.manifest)
        session = next(
            item
            for item in parsed.sessions.values()
            if item.case_id == "blind-pwn"
            and item.arm == THIN_SCAFFOLD
            and item.attempt == 1
        )
        engine = ChallengeEngine(
            self.root,
            config=load_config(self.root),
            store=self.store,
        )
        incoming = engine.challenge_input(session.identity)
        incoming.mkdir(parents=True, exist_ok=True)
        (incoming / "challenge.bin").write_bytes(b"initial-ingest-fixture")
        state = engine.add_challenge(
            session.identity,
            prompt="solve the supplied challenge",
            budget_seconds=60,
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        manifest_sha256 = state.metadata["source_manifest_sha256"]
        for split in self.manifest["splits"]:
            for case in split["cases"]:
                if case["case_id"] == session.case_id:
                    case["input_manifest_sha256"] = manifest_sha256
        self.manifest_path.write_text(
            json.dumps(self.manifest, sort_keys=True),
            encoding="utf-8",
        )
        self._freeze()
        result = prepare_promotion_session(
            self.root,
            self.frozen_path,
            session_id=session.session_id,
        )
        self.assertTrue(result["prepared"])
        prepared = self.store.load(session.identity, recover=False)
        self.assertTrue(prepared.goals)
        self.assertTrue(prepared.experiments)
        self.assertTrue(
            all(
                experiment.extra.get("adapter_seed") is True
                for experiment in prepared.experiments
            )
        )

    def test_knowledge_injected_after_prepare_blocks_provider_and_capture(
        self,
    ) -> None:
        self._freeze()
        records = self._session_records()
        session, _state = self._create_unprepared_state(records[0][0])
        prepare_promotion_session(
            self.root,
            self.frozen_path,
            session_id=records[0][0],
        )
        writeup = self.root / "late-writeup.txt"
        writeup.write_text("late answer", encoding="utf-8")
        KnowledgeStore(self.store).add(
            session.identity,
            writeup,
            source_url="https://example.invalid/late-writeup",
        )
        engine = ChallengeEngine(
            self.root,
            config=load_config(self.root),
            store=self.store,
        )
        with self.assertRaisesRegex(
            EngineError,
            "knowledge snapshot",
        ):
            engine._require_prepared_execution_fingerprint(
                self.store.load(session.identity, recover=False)
            )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "knowledge differs",
        ):
            finalize_promotion_session(
                self.root,
                self.frozen_path,
                session_id=records[0][0],
                human_interventions=0,
                secret_or_flag_leaks=0,
            )

        completed_record = records[1]
        self._create_state(*completed_record)
        completed = parse_promotion_manifest(self.manifest).sessions[
            completed_record[0]
        ]
        KnowledgeStore(self.store).add(
            completed.identity,
            writeup,
            source_url="https://example.invalid/late-capture-writeup",
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "knowledge differs",
        ):
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=completed_record[0],
                output_directory=self.root / "knowledge-contaminated",
            )

    def test_paired_sessions_require_identical_initial_context(self) -> None:
        self._freeze()
        parsed = parse_promotion_manifest(self.manifest)
        sessions = sorted(
            (
                session
                for session in parsed.sessions.values()
                if session.case_id == "blind-pwn"
            ),
            key=lambda session: (session.arm, session.attempt),
        )
        self.assertEqual(len(sessions), 6)
        bundles: list[Path] = []
        for index, session in enumerate(sessions, start=1):
            record = (
                session.session_id,
                session.case_id,
                session.split,
                session.arm,
                session.attempt,
            )
            self._create_state(
                *record,
                prompt=(
                    "paired initial context"
                    if index < 6
                    else "one-arm preloaded trajectory"
                ),
            )
            bundle = self.root / f"context-mismatch-{index}"
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=session.session_id,
                output_directory=bundle,
            )
            bundles.append(bundle)
        result = evaluate_promotion_bundles(
            self.root,
            self.frozen_path,
            bundles,
        )
        self.assertFalse(result["promotion_eligible"])
        self.assertIn(
            "paired_initial_context_mismatch:blind-pwn",
            result["collector"]["blockers"],
        )
        self.assertFalse(
            result["collector"]["all_paired_initial_contexts_match"]
        )

    def test_cohort_contamination_and_duplicate_run_ids_are_rejected(
        self,
    ) -> None:
        duplicate_identity = _manifest()
        sessions = duplicate_identity["splits"][0]["cases"][0][
            "sessions"
        ]
        sessions[1]["contest_id"] = sessions[0]["contest_id"]
        sessions[1]["category"] = sessions[0]["category"]
        sessions[1]["challenge_id"] = sessions[0]["challenge_id"]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "identity",
        ):
            parse_promotion_manifest(duplicate_identity)

        duplicate_session = _manifest()
        sessions = duplicate_session["splits"][0]["cases"][0][
            "sessions"
        ]
        sessions[1]["session_id"] = sessions[0]["session_id"]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "session_ids",
        ):
            parse_promotion_manifest(duplicate_session)

        duplicate_input = _manifest()
        first = duplicate_input["splits"][0]["cases"][0]
        second = duplicate_input["splits"][1]["cases"][0]
        second["input_manifest_sha256"] = first[
            "input_manifest_sha256"
        ]
        with self.assertRaisesRegex(
            PromotionBundleError,
            "input manifest digests",
        ):
            parse_promotion_manifest(duplicate_input)

    def test_capture_replays_state_and_artifact_hash_tamper_fails_closed(
        self,
    ) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        bundle = self.root / "bundle-one"
        capture = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=bundle,
        )
        self.assertTrue(capture["collection_complete"])

        proof = next(bundle.rglob("result.json"))
        os.chmod(proof, 0o600)
        proof.write_bytes(proof.read_bytes() + b" ")
        with self.assertRaisesRegex(
            PromotionBundleError,
            "hash mismatch",
        ):
            evaluate_promotion_bundles(
                self.root,
                self.frozen_path,
                [bundle],
            )

    def test_validly_rehashed_arm_relabel_is_rejected(self) -> None:
        self._freeze()
        record = next(
            item
            for item in self._session_records()
            if item[3] == THIN_SCAFFOLD
        )
        self._create_state(*record)
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        config = load_config(self.root)

        def relabel(current) -> None:
            fake_metadata = dict(current.metadata)
            fake_metadata["evaluation_system"] = CTF_OS_SYSTEM
            prior, _timestamp = parse_scaffold_launch_record(
                current.metadata["evaluation_scaffold_launch"]
            )
            current.metadata["evaluation_scaffold_launch"] = (
                build_scaffold_launch_binding(
                    metadata=fake_metadata,
                    configuration_epoch=current.configuration_epoch,
                    contest_id=session.contest_id,
                    category=session.category,
                    challenge_id=session.challenge_id,
                    arm=CTF_OS_SYSTEM,
                    model_id=parsed.model_id,
                    runtime_image_digest=config.runtime.image_digest,
                    command_contract_sha256=(
                        prior.command_contract_sha256
                    ),
                ).to_record()
            )

        self.store.update(session.identity, relabel)
        captured = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=self.root / "relabelled",
        )
        self.assertFalse(captured["collection_complete"])
        self.assertIn(
            "scaffold_launch_binding_mismatch",
            captured["collection_blockers"],
        )

    def test_thin_multiple_model_invocations_are_rejected(self) -> None:
        self._freeze()
        record = next(
            item
            for item in self._session_records()
            if item[3] == THIN_SCAFFOLD
        )
        self._create_state(*record)
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        state = self.store.load(session.identity, recover=False)
        launch, _timestamp = parse_scaffold_launch_record(
            state.metadata["evaluation_scaffold_launch"]
        )
        run_id = f"R-extra-{record[0]}"
        relative_paths = {
            "request_path": Path("runs") / run_id / "request.json",
            "result_path": Path("runs") / run_id / "result.json",
            "validation_path": (
                Path("runs") / run_id / "validation.json"
            ),
        }
        challenge_root = self.store.challenge_paths(session.identity).root
        for relative in relative_paths.values():
            target = challenge_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                target,
                {"run_id": run_id},
                mode=0o400,
            )

        def append_second(current) -> None:
            current.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=current.revision,
                    status=RunStatus.COMPLETED,
                    request_path=relative_paths[
                        "request_path"
                    ].as_posix(),
                    result_path=relative_paths[
                        "result_path"
                    ].as_posix(),
                    validation_path=relative_paths[
                        "validation_path"
                    ].as_posix(),
                    role="captain",
                    model=parsed.model_id,
                    origin=RunOrigin.ASSISTED_MODEL,
                    session_id=record[0],
                    configuration_epoch=current.configuration_epoch,
                    created_at=current.created_at,
                    extra={
                        "usage": {
                            "input_tokens": 1,
                            "cached_input_tokens": 0,
                            "output_tokens": 1,
                            "reasoning_output_tokens": 0,
                        },
                        "evaluation_scaffold": THIN_SCAFFOLD,
                        "execution_transport": "headless_jsonl",
                        "usage_attestation": "codex_jsonl_events",
                        "usage_attestation_valid": True,
                        "semantic_output_committed": False,
                        "logical_model_count": 1,
                        "logical_worker_roles": [],
                        "command_contract_sha256": (
                            launch.command_contract_sha256
                        ),
                        "launch_binding_sha256": (
                            launch.binding_sha256
                        ),
                    },
                )
            )

        self.store.update(session.identity, append_second)
        captured = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=self.root / "thin-double-call",
        )
        self.assertFalse(captured["collection_complete"])
        self.assertIn(
            "thin_model_invocation_count_mismatch",
            captured["collection_blockers"],
        )

    def test_full_scaffold_without_managed_cycle_is_rejected(self) -> None:
        self._freeze()
        record = next(
            item
            for item in self._session_records()
            if item[3] == CTF_OS_SYSTEM
        )
        self._create_state(*record)
        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]

        def remove_cycle(current) -> None:
            current.cycles.clear()

        self.store.update(session.identity, remove_cycle)
        captured = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=self.root / "full-no-cycle",
        )
        self.assertFalse(captured["collection_complete"])
        self.assertIn(
            "managed_cycle_missing",
            captured["collection_blockers"],
        )

    def test_duplicate_bundle_is_rejected_as_duplicate_run_id(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        bundle = self.root / "bundle-one"
        capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=bundle,
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "more than once",
        ):
            evaluate_promotion_bundles(
                self.root,
                self.frozen_path,
                [bundle, bundle],
            )

    def test_finalize_is_exact_typed_and_must_follow_all_activity(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        with self.assertRaisesRegex(
            PromotionBundleError,
            "human_interventions",
        ):
            finalize_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                human_interventions=True,
                secret_or_flag_leaks=0,
            )

        parsed = parse_promotion_manifest(self.manifest)
        session = parsed.sessions[record[0]]
        state = self.store.load(session.identity, recover=False)
        finalized_at = state.metadata["evaluation_finalized_at"]

        def late_activity(current) -> None:
            current.runs.append(
                RunReference(
                    id="R-after-finalize",
                    base_revision=current.revision,
                    status=RunStatus.COMPLETED,
                    role="tool",
                    created_at=_later(finalized_at, 1),
                )
            )

        self.store.update(session.identity, late_activity)
        captured = capture_promotion_session(
            self.root,
            self.frozen_path,
            session_id=record[0],
            output_directory=self.root / "late-bundle",
        )
        self.assertFalse(captured["collection_complete"])
        self.assertIn(
            "activity_occurred_after_finalization",
            captured["collection_blockers"],
        )

    def test_fingerprint_change_after_prepare_blocks_capture(self) -> None:
        self._freeze()
        record = self._session_records()[0]
        self._create_state(*record)
        config_path = self.root / ".ctfos" / "engine.toml"
        atomic_write_text(
            config_path,
            set_runtime_image_digest(
                default_config_text(),
                "sha256:" + "4" * 64,
            ),
            mode=0o600,
        )
        with self.assertRaisesRegex(
            PromotionBundleError,
            "fingerprint",
        ):
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=self.root / "wrong-fingerprint",
            )

    def test_missing_bundle_returns_closed_collector_and_gate(self) -> None:
        self._freeze()
        result = evaluate_promotion_bundles(
            self.root,
            self.frozen_path,
            [],
        )
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["complete_evidence"])
        self.assertTrue(
            any(
                blocker.startswith("missing_session_bundle:")
                for blocker in result["collector"]["blockers"]
            )
        )
        self.assertIn(
            "promotion_evidence_incomplete",
            result["blockers"],
        )

    def test_cli_routes_freeze_capture_and_closed_compare(self) -> None:
        record = self._session_records()[0]
        bundle = self.root / "cli-bundle"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            freeze_status = cli.main(
                [
                    "benchmark",
                    "freeze",
                    "--manifest",
                    str(self.manifest_path),
                    "--output",
                    str(self.frozen_path),
                ],
                root=self.root,
            )
        self._create_state(*record)
        with redirect_stdout(stdout), redirect_stderr(stderr):
            capture_status = cli.main(
                [
                    "benchmark",
                    "capture",
                    "--manifest",
                    str(self.frozen_path),
                    "--session",
                    record[0],
                    "--output",
                    str(bundle),
                ],
                root=self.root,
            )
            compare_status = cli.main(
                [
                    "benchmark",
                    "compare",
                    "--manifest",
                    str(self.frozen_path),
                    "--bundle",
                    str(bundle),
                ],
                root=self.root,
            )
        self.assertEqual(
            (freeze_status, capture_status, compare_status),
            (0, 0, 0),
            stderr.getvalue(),
        )
        decoder = json.JSONDecoder()
        values: list[object] = []
        remaining = stdout.getvalue().lstrip()
        while remaining:
            value, offset = decoder.raw_decode(remaining)
            values.append(value)
            remaining = remaining[offset:].lstrip()
        self.assertEqual(len(values), 3)
        self.assertTrue(values[0]["frozen"])
        self.assertTrue(values[1]["captured"])
        self.assertFalse(values[2]["promotion_eligible"])
        self.assertTrue(
            any(
                blocker.startswith("missing_session_bundle:")
                for blocker in values[2]["collector"]["blockers"]
            )
        )

    def test_complete_real_bundle_collection_stays_closed_without_proofs(
        self,
    ) -> None:
        self._freeze()
        bundles: list[Path] = []
        for record in self._session_records():
            self._create_state(*record)
            bundle = self.root / "bundles" / record[0]
            capture_promotion_session(
                self.root,
                self.frozen_path,
                session_id=record[0],
                output_directory=bundle,
            )
            bundles.append(bundle)

        result = evaluate_promotion_bundles(
            self.root,
            self.frozen_path,
            bundles,
        )

        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["complete_evidence"])
        self.assertEqual(result["decision"], "do_not_promote")
        self.assertEqual(result["collector"]["blockers"], [])
        self.assertEqual(
            result["collector"]["verified_session_bundles"],
            84,
        )
        self.assertIsNone(result["metrics"])
        self.assertIn(
            "candidate_proof_coverage_incomplete",
            result["blockers"],
        )
        self.assertIn(
            "candidate_reproduction_coverage_incomplete",
            result["blockers"],
        )
        self.assertFalse(result["automatic_promotion"])
        self.assertFalse(result["automatic_submission"])
        self.assertFalse(result["automatic_challenge_switch"])


if __name__ == "__main__":
    unittest.main()
