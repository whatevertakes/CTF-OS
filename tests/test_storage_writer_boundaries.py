from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.knowledge as knowledge_module
import ctf_os.lifecycle as lifecycle_module
import ctf_os.workspace_publish as workspace_publish_module
from ctf_os.config import load_config
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.knowledge import KnowledgeError, KnowledgeStore
from ctf_os.lifecycle import close_challenge, export_challenge
from ctf_os.models import (
    ChallengeIdentity,
    RunOrigin,
    RunReference,
    RunStatus,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.storage import storage_inventory
from ctf_os.store import ChallengeLock
from ctf_os.workspace_publish import publish_builder_file


class StorageWriterBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("Quota CTF", "rev", "writer")
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"immutable-input")
        self.engine = ChallengeEngine(self.root)
        self.engine.add_challenge(
            self.identity,
            prompt="verify every storage writer boundary",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def limited_engine(self, quota_bytes: int = 1) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                challenge_storage_quota_bytes=quota_bytes,
            ),
        )
        return ChallengeEngine(self.root, config=config)

    def add_builder_run(self) -> tuple[str, Path]:
        run_id = "MR-builder-quota"
        run_paths = self.engine.store.create_run(
            self.identity,
            run_id=run_id,
            request={"kind": "model", "role": "builder"},
        )
        self.engine.store.write_run_result(
            self.identity,
            run_id,
            {"status": "completed"},
        )
        self.engine.store.write_run_validation(
            self.identity,
            run_id,
            {"ok": True},
        )
        workspace = run_paths.root / "workspace"
        workspace.mkdir()
        source = workspace / "solve.py"
        source.write_bytes(b"print('bounded')\n")
        challenge_root = self.engine.store.challenge_paths(
            self.identity
        ).root

        def add_run(state: object) -> None:
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=state.revision,
                    status=RunStatus.COMPLETED,
                    request_path=run_paths.request.relative_to(
                        challenge_root
                    ).as_posix(),
                    result_path=run_paths.result.relative_to(
                        challenge_root
                    ).as_posix(),
                    validation_path=run_paths.validation.relative_to(
                        challenge_root
                    ).as_posix(),
                    role="builder",
                    origin=RunOrigin.MANAGED_MODEL,
                    configuration_epoch=state.configuration_epoch,
                )
            )

        self.engine.store.update(self.identity, add_run)
        return run_id, source

    def test_knowledge_quota_rejects_before_copy_or_index_write(self) -> None:
        source = self.root / "operator-notes.md"
        source.write_text("bounded reviewed notes\n", encoding="utf-8")
        store = KnowledgeStore(
            self.engine.store,
            quota_bytes=1,
        )
        paths = self.engine.store.challenge_paths(self.identity)
        before_index = (
            (paths.knowledge / "index.json").read_bytes()
            if (paths.knowledge / "index.json").exists()
            else None
        )
        with (
            mock.patch.object(
                knowledge_module,
                "copy_bounded_regular",
                wraps=knowledge_module.copy_bounded_regular,
            ) as copy_call,
            mock.patch.object(
                knowledge_module,
                "_write_index",
                wraps=knowledge_module._write_index,
            ) as index_write,
            self.assertRaisesRegex(KnowledgeError, "storage quota"),
        ):
            store.add(
                self.identity,
                source,
                source_url="https://example.test/reviewed-notes",
            )
        copy_call.assert_not_called()
        index_write.assert_not_called()
        self.assertEqual(
            (
                (paths.knowledge / "index.json").read_bytes()
                if (paths.knowledge / "index.json").exists()
                else None
            ),
            before_index,
        )
        self.assertEqual(list((paths.knowledge / "documents").glob("*")), [])

    def test_close_and_export_quota_reject_before_accounted_writes(self) -> None:
        engine = self.limited_engine()
        paths = engine.store.challenge_paths(self.identity)
        state_before = paths.state.read_bytes()
        context_before = paths.current_context.read_bytes()
        exports_before = tuple(paths.exports.iterdir())

        with (
            mock.patch.object(
                lifecycle_module,
                "_close_challenge_locked",
                wraps=lifecycle_module._close_challenge_locked,
            ) as close_write,
            self.assertRaisesRegex(EngineError, "storage quota"),
        ):
            close_challenge(engine, self.identity, portability="portable")
        close_write.assert_not_called()
        self.assertEqual(paths.state.read_bytes(), state_before)
        self.assertEqual(
            list((paths.runtime / "closure-intents").glob("*.json")),
            [],
        )
        self.assertFalse((paths.artifacts / "closures").exists())

        with (
            mock.patch.object(
                lifecycle_module,
                "_reconcile_closure_intents",
                wraps=lifecycle_module._reconcile_closure_intents,
            ) as reconcile,
            self.assertRaisesRegex(EngineError, "storage quota"),
        ):
            export_challenge(engine, self.identity)
        reconcile.assert_not_called()
        self.assertEqual(paths.state.read_bytes(), state_before)
        self.assertEqual(paths.current_context.read_bytes(), context_before)
        self.assertEqual(tuple(paths.exports.iterdir()), exports_before)

    def test_export_admits_exact_planned_documents_near_quota(self) -> None:
        inventory = storage_inventory(self.engine.store, self.identity)
        requested = lifecycle_module._export_admission_reservation(
            self.engine,
            self.identity,
            include_closure=False,
            redacted=False,
        )
        self.assertLess(
            requested,
            lifecycle_module.MAX_CANONICAL_STATE_BYTES,
        )
        engine = self.limited_engine(
            inventory["total_bytes"] + requested
        )
        destination = export_challenge(engine, self.identity)
        self.assertTrue((destination / "state.json").is_file())
        self.assertTrue((destination / "summary.md").is_file())

    def test_workspace_publish_quota_rejects_before_intent_copy_or_state(self) -> None:
        run_id, source = self.add_builder_run()
        engine = self.limited_engine()
        paths = engine.store.challenge_paths(self.identity)
        state_before = paths.state.read_bytes()
        with (
            mock.patch.object(
                workspace_publish_module,
                "atomic_write_json",
                wraps=workspace_publish_module.atomic_write_json,
            ) as intent_write,
            mock.patch.object(
                engine.store,
                "update",
                wraps=engine.store.update,
            ) as state_update,
            self.assertRaisesRegex(EngineError, "storage quota"),
        ):
            publish_builder_file(
                engine,
                self.identity,
                run_id=run_id,
                staged_path=source.name,
                destination="nested/solve.py",
                base_workspace_revision=0,
                base_sha256=None,
            )
        intent_write.assert_not_called()
        state_update.assert_not_called()
        self.assertEqual(paths.state.read_bytes(), state_before)
        self.assertFalse(paths.artifacts.joinpath("workspace").exists())
        self.assertEqual(
            list(
                (paths.runtime / "workspace-publish-intents").glob("*.json")
            ),
            [],
        )

    def test_public_writers_fail_closed_while_session_is_owned(self) -> None:
        run_id, source = self.add_builder_run()
        notes = self.root / "locked-notes.md"
        notes.write_text("operator text\n", encoding="utf-8")
        paths = self.engine.store.challenge_paths(self.identity)
        with ChallengeLock(
            paths.runtime / "session.lock",
            timeout=0,
        ) as session_lock:
            session_lock.acquire()
            with self.assertRaises(SessionAlreadyRunning):
                export_challenge(self.engine, self.identity)
            with self.assertRaises(SessionAlreadyRunning):
                close_challenge(self.engine, self.identity)
            with self.assertRaises(SessionAlreadyRunning):
                publish_builder_file(
                    self.engine,
                    self.identity,
                    run_id=run_id,
                    staged_path=source.name,
                    destination=source.name,
                    base_workspace_revision=0,
                    base_sha256=None,
                )
            with self.assertRaises(KnowledgeError):
                KnowledgeStore(self.engine.store).add(
                    self.identity,
                    notes,
                    source_url="https://example.test/locked-notes",
                )


if __name__ == "__main__":
    unittest.main()
