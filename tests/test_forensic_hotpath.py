from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.forensic_index_execution import (
    FORENSIC_INDEX_EXECUTION_PROTOCOL,
)
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    Provenance,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION


REPOSITORY = Path(__file__).resolve().parent.parent
PRODUCER_PATH = (
    REPOSITORY / "ctf-os-image/templates/forensic/evidence_index.py"
)
SPEC = importlib.util.spec_from_file_location(
    "forensic_index_producer_for_hotpath_test",
    PRODUCER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PRODUCER
SPEC.loader.exec_module(PRODUCER)

IMAGE_DIGEST = "sha256:" + ("8" * 64)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_provenance(
    source_root: Path,
    metadata_path: Path,
    tree_path: Path,
) -> None:
    tree = bytearray()
    file_count = 0
    total_bytes = 0
    for path in sorted(
        source_root.rglob("*"),
        key=lambda item: os.fsencode(
            item.relative_to(source_root).as_posix()
        ),
    ):
        relative = path.relative_to(source_root).as_posix().encode()
        mode = f"{stat.S_IMODE(path.stat().st_mode):o}".encode()
        if path.is_dir():
            tree.extend(b"D\0" + mode + b"\0" + relative + b"\0")
            continue
        payload = path.read_bytes()
        tree.extend(
            b"F\0"
            + mode
            + b"\0"
            + relative
            + b"\0"
            + _sha256(payload).encode()
            + b"\0"
        )
        file_count += 1
        total_bytes += len(payload)
    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_bytes(tree)
    metadata_path.write_text(
        json.dumps(
            {
                "inventory": {
                    "algorithm": "sha256",
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                },
                "schema_version": 1,
                "source": {
                    "mount_read_only": True,
                    "path": str(source_root),
                    "present": True,
                    "read_only_expected": True,
                    "writable_override_used": False,
                },
                "status": "initialized",
                "tree": {
                    "digest": _sha256(bytes(tree)),
                    "format": "ctf-tree-v1-nul",
                    "path": str(tree_path),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def _producer_stdout(source_root: Path, scratch: Path) -> bytes:
    metadata_path = scratch / "challenge.json"
    tree_path = scratch / "challenge.tree"
    _write_provenance(source_root, metadata_path, tree_path)
    document = PRODUCER.build_evidence_index(
        source_root,
        tree_path,
        metadata_path,
    )
    document["source"]["path"] = "/challenge"
    for record in document["records"]:
        relative = Path(record["pointer"]["path"]).relative_to(
            source_root
        )
        record["pointer"]["path"] = (
            "/challenge/" + relative.as_posix()
        )
    record_chain = hashlib.sha256()
    for record in document["records"]:
        record_chain.update(PRODUCER._canonical_json(record))
        record_chain.update(b"\n")
    document["index_sha256"] = record_chain.hexdigest()
    return PRODUCER._canonical_json(document) + b"\n"


class ForensicIndexSandbox:
    scope_fingerprint = "f" * 64

    def __init__(
        self,
        work: Path,
        stdout_payload: bytes,
        *,
        mutate_source=None,
    ) -> None:
        self.work = work
        self.stdout_payload = stdout_payload
        self.mutate_source = mutate_source
        self.specs = []

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds

    def run(self, spec):
        self.specs.append(spec)
        raw = self.work / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        stdout.write_bytes(self.stdout_payload)
        stderr.write_bytes(b"")
        if self.mutate_source is not None:
            self.mutate_source()
        return SandboxResult(
            run_id="forensic-index-sandbox",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=3,
            stdout_summary="bounded forensic evidence index",
            stderr_summary="",
            stdout_bytes=len(self.stdout_payload),
            stderr_bytes=0,
            stdout_path="/work/raw/stdout.log",
            stderr_path="/work/raw/stderr.log",
            stdout_stored_bytes=len(self.stdout_payload),
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
        )

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("test artifact exceeds bound")
        return ArtifactRef(
            locator=locator,
            sha256=_sha256(payload),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(self, *args, **kwargs):
        raise AssertionError("Forensic index uses the normal sandbox path")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class ForensicIndexHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Forensic CTF",
            "forensics",
            "Evidence case",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _engine(
        self,
        *,
        mutate_source=None,
    ) -> tuple[ChallengeEngine, dict[str, ForensicIndexSandbox]]:
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "traffic.pcapng").write_bytes(
            b"\x0a\x0d\x0d\x0a" + b"packet"
        )
        nested = incoming / "nested"
        nested.mkdir()
        (nested / "case.evtx").write_bytes(b"ElfFile\0event")
        payload = _producer_stdout(incoming, self.root / "producer")
        holder: dict[str, ForensicIndexSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = holder.get("sandbox")
            if sandbox is None:
                sandbox = ForensicIndexSandbox(
                    work,
                    payload,
                    mutate_source=mutate_source,
                )
                holder["sandbox"] = sandbox
            return sandbox

        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
            ),
        )
        return (
            ChallengeEngine(
                self.root,
                config=config,
                sandbox_factory=sandbox_factory,
            ),
            holder,
        )

    def _bound_seed(self, engine: ChallengeEngine):
        initial = engine.add_challenge(
            self.identity,
            prompt="index the immutable evidence",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=lambda digest: {
                "ok": digest == IMAGE_DIGEST,
                "schema_version": 2,
                "capabilities": {},
            },
        )
        _reserved, session_id = orchestrator._reserve_session(
            self.identity,
            "S-forensic-hotpath",
        )
        synchronized = engine.synchronize_managed_adapter_seed_plan(
            self.identity,
            session_id,
        )
        legacy_ids = {
            item.id
            for item in initial.experiments
            if item.extra.get("adapter_seed") is True
        }
        seed = next(
            experiment
            for experiment in synchronized.experiments
            if (
                experiment.id not in legacy_ids
                and experiment.extra.get("adapter_spec_template_id")
                == "file_inventory"
            )
        )
        _reserved, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        orchestrator._mark_action_selection(
            self.identity,
            session_id,
            cycle.id,
            (seed.id,),
        )
        return seed

    def test_explicit_seed_executes_and_authorizes_only_fact_progress(
        self,
    ) -> None:
        engine, holder = self._engine()
        seed = self._bound_seed(engine)

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(seed.id,),
        )

        completed = next(
            item for item in state.experiments if item.id == seed.id
        )
        self.assertIs(completed.status, ExperimentStatus.COMPLETED)
        evaluation = completed.result["forensic_index_execution"]
        self.assertTrue(evaluation["confirmed"])
        self.assertEqual(
            evaluation["protocol"],
            FORENSIC_INDEX_EXECUTION_PROTOCOL,
        )
        self.assertEqual(len(holder["sandbox"].specs), 1)
        self.assertIsNone(holder["sandbox"].specs[0].network_target)
        tool_runs = [
            item
            for item in state.runs
            if item.id == evaluation["envelope"]["run"]["id"]
        ]
        self.assertEqual(len(tool_runs), 1)
        self.assertEqual(len(state.receipts), 1)
        self.assertEqual(
            tool_runs[0].extra["forensic_index_execution"],
            evaluation,
        )
        self.assertEqual(
            state.receipts[0].extra["forensic_index_execution"],
            evaluation,
        )
        facts = [
            item
            for item in state.facts
            if "forensic_evidence_index" in item.extra
        ]
        progress = [
            item
            for item in state.progress_markers
            if "forensic_evidence_index" in item.extra
        ]
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].provenance, Provenance.EXECUTED)
        self.assertEqual(len(progress), 1)
        self.assertIs(state.status, ChallengeStatus.TRIAGING)
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])
        state.validate()

    def test_source_mutation_during_transport_fails_closed(self) -> None:
        incoming_file = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
            / "traffic.pcapng"
        )
        engine, _ = self._engine(
            mutate_source=lambda: incoming_file.write_bytes(b"mutated"),
        )
        seed = self._bound_seed(engine)

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(seed.id,),
        )
        terminal = next(
            item for item in state.experiments if item.id == seed.id
        )
        self.assertIs(terminal.status, ExperimentStatus.FAILED)
        self.assertFalse(
            terminal.result["forensic_index_execution"]["confirmed"]
        )
        self.assertIn(
            terminal.result["forensic_index_execution"]["reason_code"],
            {
                "source_manifest_mismatch",
                "source_inventory_mismatch",
                "source_prefix_mismatch",
                "semantic_coverage_incomplete",
            },
        )
        self.assertFalse(
            any(
                "forensic_evidence_index" in item.extra
                for item in state.facts
            )
        )
        self.assertEqual(state.submissions, [])

    def test_pre_replace_guard_rejects_source_toctou(self) -> None:
        engine, _ = self._engine()
        seed = self._bound_seed(engine)
        original_update = engine.store.update
        changed = False

        def mutate_at_pre_replace(*args, **kwargs):
            guard = kwargs.get("pre_replace_guard")
            if guard is not None:
                def changed_guard():
                    nonlocal changed
                    if not changed:
                        source = (
                            engine.challenge_input(self.identity)
                            / "traffic.pcapng"
                        )
                        source.write_bytes(b"changed before replace")
                        changed = True
                    return guard()

                kwargs["pre_replace_guard"] = changed_guard
            return original_update(*args, **kwargs)

        with patch.object(
            engine.store,
            "update",
            side_effect=mutate_at_pre_replace,
        ):
            with self.assertRaisesRegex(
                Exception,
                "Forensic index changed|independently re-read",
            ):
                engine.execute_registered_experiments(
                    self.identity,
                    experiment_ids=(seed.id,),
                )

        self.assertTrue(changed)
        state = engine.store.load(self.identity)
        self.assertFalse(
            any(
                "forensic_evidence_index" in item.extra
                for item in state.facts
            )
        )
        self.assertEqual(state.submissions, [])

    def test_pre_replace_guard_rejects_evaluation_artifact_tamper(
        self,
    ) -> None:
        engine, _ = self._engine()
        seed = self._bound_seed(engine)
        original_update = engine.store.update
        changed = False

        def mutate_at_pre_replace(*args, **kwargs):
            guard = kwargs.get("pre_replace_guard")
            if guard is not None:
                def changed_guard():
                    nonlocal changed
                    if not changed:
                        snapshots = (
                            engine.store.challenge_paths(
                                self.identity
                            ).artifacts
                            / "snapshots"
                        )
                        artifact = next(
                            snapshots.glob(
                                "*forensic-index-evaluation.json"
                            )
                        )
                        artifact.chmod(0o600)
                        artifact.write_bytes(b'{"tampered":true}\n')
                        changed = True
                    return guard()

                kwargs["pre_replace_guard"] = changed_guard
            return original_update(*args, **kwargs)

        with patch.object(
            engine.store,
            "update",
            side_effect=mutate_at_pre_replace,
        ):
            with self.assertRaisesRegex(
                Exception,
                "Forensic evaluation artifact changed",
            ):
                engine.execute_registered_experiments(
                    self.identity,
                    experiment_ids=(seed.id,),
                )

        self.assertTrue(changed)
        state = engine.store.load(self.identity)
        self.assertFalse(
            any(
                "forensic_evidence_index" in item.extra
                for item in state.facts
            )
        )
        self.assertEqual(state.submissions, [])


if __name__ == "__main__":
    unittest.main()
