from __future__ import annotations

import io
import hashlib
import json
import stat
import tempfile
import threading
import unittest
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.adapters import get_adapter
from ctf_os.codex import Role
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    data_transcript_v1_reset_commitment_sha256,
)
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.data_transcript_hotpath import (
    DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
    DATA_TRANSCRIPT_STATE_KEY,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_CRYPTO,
    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
)
from ctf_os.live_broker import inspect_state
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    RunOrigin,
    RunReference,
    RunStatus,
)
from tests import test_crypto_engine as crypto_support
from tests import test_misc_engine as misc_support
from tests.test_managed_category_hotpaths import (
    _execute_full_managed_cycle,
)


class ManagedOraclePreissueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _seed_running_builder(
        engine: ChallengeEngine,
        identity,
        *,
        base_revision: int | None = None,
    ) -> tuple[str, str]:
        builder_run_id = "R-managed-preissue-builder"
        experiment_id = "E-managed-preissue-gate"
        if base_revision is None:
            # Model the real managed lifecycle: an issued preissue is
            # durably visible before the Builder takes its base snapshot.
            engine.store.update(
                identity,
                lambda state: state.extra.update(
                    {
                        "managed_preissue_builder_barrier_revision": (
                            state.revision + 1
                        )
                    }
                ),
            )

        def seed(state):
            state.runs.append(
                RunReference(
                    id=builder_run_id,
                    base_revision=(
                        state.revision
                        if base_revision is None
                        else base_revision
                    ),
                    status=RunStatus.COMPLETED,
                    result_path=(
                        f"runs/{builder_run_id}/result.json"
                    ),
                    validation_path=(
                        f"runs/{builder_run_id}/validation.json"
                    ),
                    role=Role.BUILDER.value,
                    origin=RunOrigin.MANAGED_MODEL,
                    configuration_epoch=state.configuration_epoch,
                    extra={"semantic_merge": True},
                )
            )
            state.experiments.append(
                Experiment(
                    id=experiment_id,
                    hypothesis_ids=[],
                    command="ctfos-engine:typed-gate-v1",
                    expected_observation="hidden oracle verdict",
                    keep_if="the hidden oracle passes",
                    drop_if="the hidden oracle rejects",
                    timeout_seconds=300,
                    kind=ExperimentKind.PROBE,
                    status=ExperimentStatus.RUNNING,
                    source_run_id=builder_run_id,
                )
            )

        engine.store.update(identity, seed)
        return builder_run_id, experiment_id

    @staticmethod
    def _preissue_crypto(engine, identity):
        workspace = engine._workspace(engine.store.load(identity))
        with tempfile.TemporaryDirectory() as operator_temp:
            root = Path(operator_temp)
            variant = root / "variant.json"
            expected = root / "expected.bin"
            variant.write_bytes((workspace / "variant.json").read_bytes())
            expected.write_bytes((workspace / "variant.out").read_bytes())
            result = engine.preissue_managed_crypto_oracle(
                identity,
                variant_parameters_path=variant,
                variant_expected_output_path=expected,
                mutation_id="operator-hidden-variant",
            )
        (workspace / "variant.json").unlink()
        (workspace / "variant.out").unlink()
        return result

    def test_challenge_workspace_cannot_be_an_oracle_source(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            with self.assertRaisesRegex(
                EngineError,
                "operator-only.*outside the challenge root",
            ):
                engine.preissue_managed_crypto_oracle(
                    case.identity,
                    variant_parameters_path=(
                        engine._workspace(
                            engine.store.load(case.identity)
                        )
                        / "variant.json"
                    ),
                    variant_expected_output_path=(
                        engine._workspace(
                            engine.store.load(case.identity)
                        )
                        / "variant.out"
                    ),
                    mutation_id="workspace-bypass",
                )
            state = engine.store.load(case.identity)
            self.assertNotIn(
                MANAGED_ORACLE_PREISSUE_STATE_KEY,
                state.extra,
            )
        finally:
            case.tearDown()

    def test_final_component_symlink_cannot_be_an_oracle_source(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            with tempfile.TemporaryDirectory() as operator_temp:
                root = Path(operator_temp)
                target = root / "real.json"
                target.write_text('{"variant":2}\n', encoding="utf-8")
                link = root / "variant.json"
                link.symlink_to(target)
                expected = root / "expected.bin"
                expected.write_bytes(b"answer\n")
                with self.assertRaisesRegex(
                    EngineError,
                    "operator-only.*regular host file",
                ):
                    engine.preissue_managed_crypto_oracle(
                        case.identity,
                        variant_parameters_path=link,
                        variant_expected_output_path=expected,
                        mutation_id="symlink-bypass",
                    )
            self.assertNotIn(
                MANAGED_ORACLE_PREISSUE_STATE_KEY,
                engine.store.load(case.identity).extra,
            )
        finally:
            case.tearDown()

    def test_host_path_bytes_and_input_hash_never_enter_model_context(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            (workspace / "variant.json").unlink()
            (workspace / "variant.out").unlink()
            secret_bytes = b"operator-only-hidden-oracle-9f27\n"
            with tempfile.TemporaryDirectory() as operator_temp:
                root = Path(operator_temp)
                variant = root / "very-secret-variant.json"
                expected = root / "very-secret-expected.bin"
                variant.write_text('{"secret_variant":927}\n', encoding="utf-8")
                expected.write_bytes(secret_bytes)
                _state, record = engine.preissue_managed_crypto_oracle(
                    case.identity,
                    variant_parameters_path=variant,
                    variant_expected_output_path=expected,
                    mutation_id="context-redaction",
                )
                host_paths = (str(variant), str(expected))
                input_hashes = (
                    hashlib.sha256(variant.read_bytes()).hexdigest(),
                    hashlib.sha256(secret_bytes).hexdigest(),
                )
            state = engine.store.load(case.identity)
            pack = build_context_pack(
                state,
                get_adapter(state.category),
                state_path=engine.store.challenge_paths(
                    case.identity
                ).state,
                role=Role.BUILDER.value,
            )
            worker_payload = pack.text
            for forbidden in (
                *host_paths,
                *input_hashes,
                secret_bytes.decode("ascii").strip(),
            ):
                self.assertNotIn(forbidden, worker_payload)
            public_record = state.extra[
                MANAGED_ORACLE_PREISSUE_STATE_KEY
            ][record["preissue_id"]]
            self.assertNotIn("path", json.dumps(public_record))
            self.assertNotIn("inputs", json.dumps(public_record))
        finally:
            case.tearDown()

    def test_transcript_preissue_seals_peer_and_hides_private_inputs(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            marker = b"operator-transcript-secret-6f3c"
            with tempfile.TemporaryDirectory() as operator_temp:
                root = Path(operator_temp)
                peer = root / "peer.py"
                peer.write_bytes(
                    b"#!/usr/bin/python3\n# " + marker + b"\n"
                )
                peer.chmod(0o700)
                peer_data = root / "peer-data.bin"
                peer_data.write_bytes(b"")
                peer_sha256 = hashlib.sha256(
                    peer.read_bytes()
                ).hexdigest()
                peer_data_sha256 = hashlib.sha256(b"").hexdigest()
                host_paths = (str(peer), str(peer_data))

                state, record = (
                    engine.preissue_managed_crypto_transcript(
                        case.identity,
                        peer_path=peer,
                        peer_data_path=peer_data,
                    )
                )

            self.assertEqual(
                record["kind"],
                MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
            )
            expected_reset = (
                data_transcript_v1_reset_commitment_sha256(
                    category="crypto",
                    peer_sha256=peer_sha256,
                    peer_size_bytes=len(
                        b"#!/usr/bin/python3\n# " + marker + b"\n"
                    ),
                    peer_data_sha256=peer_data_sha256,
                    peer_data_size_bytes=0,
                )
            )
            self.assertEqual(
                record["reset_commitment_sha256"],
                expected_reset,
            )
            public_json = json.dumps(record, sort_keys=True)
            for forbidden in (
                *host_paths,
                peer_sha256,
                peer_data_sha256,
                marker.decode("ascii"),
            ):
                self.assertNotIn(forbidden, public_json)

            inputs = [
                item
                for item in state.artifacts
                if item.extra.get("preissue_id")
                == record["preissue_id"]
                and item.extra.get("kind")
                == "managed_oracle_preissue_input"
            ]
            self.assertEqual(
                {
                    item.extra.get("purpose")
                    for item in inputs
                },
                {"transcript_peer", "transcript_peer_data"},
            )
            paths = engine.store.challenge_paths(case.identity)
            by_purpose = {
                str(item.extra["purpose"]): item for item in inputs
            }
            self.assertEqual(
                stat.S_IMODE(
                    (
                        paths.root
                        / by_purpose["transcript_peer"].path
                    ).stat().st_mode
                ),
                0o500,
            )
            self.assertEqual(
                stat.S_IMODE(
                    (
                        paths.root
                        / by_purpose["transcript_peer_data"].path
                    ).stat().st_mode
                ),
                0o400,
            )
            self.assertEqual(
                by_purpose["transcript_peer_data"].size,
                0,
            )
            self.assertTrue(
                all(
                    item.extra.get("context_visibility")
                    == "engine_private"
                    for item in inputs
                )
            )
            context = build_context_pack(
                state,
                get_adapter(state.category),
                state_path=paths.state,
                role=Role.BUILDER.value,
            ).text
            broker = json.dumps(
                inspect_state(state, "state"),
                sort_keys=True,
            )
            for forbidden in (
                *host_paths,
                peer_sha256,
                peer_data_sha256,
                marker.decode("ascii"),
            ):
                self.assertNotIn(forbidden, context)
                self.assertNotIn(forbidden, broker)
            state.validate()
        finally:
            case.tearDown()

    def test_managed_raw_crypto_oracle_locator_is_rejected(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            with self.assertRaisesRegex(
                EngineError,
                "forbids raw oracle locators",
            ):
                engine.prove_crypto_metamorphic_candidate(
                    case.identity,
                    "C-crypto-candidate",
                    solver_locator="solver.py",
                    original_parameters_locator="original.json",
                    variant_parameters_locator="variant.json",
                    variant_expected_output_locator="variant.out",
                    mutation_id="builder-controlled",
                    _session_owned=True,
                )
            self.assertEqual(sandbox.proof_calls, [])
        finally:
            case.tearDown()

    def test_private_oracle_mutation_fails_before_crypto_execution(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            _state, record = self._preissue_crypto(engine, case.identity)
            builder_run_id, experiment_id = self._seed_running_builder(
                engine,
                case.identity,
            )
            state = engine.store.load(case.identity)
            artifact = next(
                item
                for item in state.artifacts
                if item.extra.get("preissue_id")
                == record["preissue_id"]
                and item.extra.get("purpose")
                == "variant_expected_output"
            )
            private_path = (
                engine.store.challenge_paths(case.identity).root
                / artifact.path
            )
            private_path.chmod(0o600)
            private_path.write_bytes(b"hostile oracle replacement\n")
            private_path.chmod(0o400)

            with self.assertRaisesRegex(
                EngineError,
                "private input|private manifest|changed",
            ):
                engine.prove_crypto_metamorphic_candidate(
                    case.identity,
                    "C-crypto-candidate",
                    solver_locator="solver.py",
                    original_parameters_locator="original.json",
                    oracle_preissue_id=str(record["preissue_id"]),
                    _session_owned=True,
                    _managed_builder_run_id=builder_run_id,
                    _managed_experiment_id=experiment_id,
                )
            self.assertEqual(sandbox.proof_calls, [])
            current = engine.store.load(case.identity)
            self.assertEqual(
                current.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
                    record["preissue_id"]
                ]["status"],
                "unused",
            )
        finally:
            case.tearDown()

    def test_one_preissue_cannot_be_consumed_twice(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            _state, record = self._preissue_crypto(engine, case.identity)
            builder_run_id, experiment_id = self._seed_running_builder(
                engine,
                case.identity,
            )
            first = engine._consume_managed_oracle_preissue(
                case.identity,
                preissue_id=str(record["preissue_id"]),
                expected_kind=MANAGED_ORACLE_PREISSUE_CRYPTO,
                builder_run_id=builder_run_id,
                experiment_id=experiment_id,
            )
            self.assertEqual(
                first.manifest.preissue_id,
                record["preissue_id"],
            )
            with self.assertRaisesRegex(
                EngineError,
                "consumed|stale",
            ):
                engine._consume_managed_oracle_preissue(
                    case.identity,
                    preissue_id=str(record["preissue_id"]),
                    expected_kind=MANAGED_ORACLE_PREISSUE_CRYPTO,
                    builder_run_id=builder_run_id,
                    experiment_id=experiment_id,
                )
            current = engine.store.load(case.identity)
            consumed = current.extra[
                MANAGED_ORACLE_PREISSUE_STATE_KEY
            ][record["preissue_id"]]
            self.assertEqual(consumed["status"], "consumed")
            self.assertEqual(
                consumed["consumed_by_builder_run_id"],
                builder_run_id,
            )
        finally:
            case.tearDown()

    def test_concurrent_consume_has_exactly_one_winner(self) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            _state, record = self._preissue_crypto(engine, case.identity)
            builder_run_id, experiment_id = self._seed_running_builder(
                engine,
                case.identity,
            )
            barrier = threading.Barrier(2)

            def consume():
                barrier.wait(timeout=5)
                return engine._consume_managed_oracle_preissue(
                    case.identity,
                    preissue_id=str(record["preissue_id"]),
                    expected_kind=MANAGED_ORACLE_PREISSUE_CRYPTO,
                    builder_run_id=builder_run_id,
                    experiment_id=experiment_id,
                )

            successes = []
            failures = []
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(consume) for _ in range(2)]
                for future in futures:
                    try:
                        successes.append(future.result(timeout=10))
                    except EngineError as error:
                        failures.append(error)
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            current = engine.store.load(case.identity)
            record_state = current.extra[
                MANAGED_ORACLE_PREISSUE_STATE_KEY
            ][record["preissue_id"]]
            self.assertEqual(record_state["status"], "consumed")
        finally:
            case.tearDown()

    def test_session_boundary_recovers_crash_left_transcript_reservation(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        try:
            engine, _sandbox = case._engine()
            with tempfile.TemporaryDirectory() as operator_temp:
                operator_root = Path(operator_temp)
                peer = operator_root / "peer"
                peer.write_bytes(b"#!/bin/sh\nexit 0\n")
                peer.chmod(0o500)
                peer_data = operator_root / "peer-data.bin"
                peer_data.write_bytes(b"recovery-seed")
                _state, record = (
                    engine.preissue_managed_crypto_transcript(
                        case.identity,
                        peer_path=peer,
                        peer_data_path=peer_data,
                    )
                )

            engine.store.update(
                case.identity,
                lambda state: state.extra.update(
                    {"transcript_recovery_test_epoch": 1}
                ),
            )
            builder_run_id, experiment_id = (
                self._seed_running_builder(
                    engine,
                    case.identity,
                )
            )
            recipe_payload = b'{"data_only":"pinned"}\n'
            recipe_sha256 = hashlib.sha256(
                recipe_payload
            ).hexdigest()
            recipe_id = "A-transcript-recovery-recipe"
            recipe_relative = (
                f"artifacts/snapshots/{recipe_id}.json"
            )
            recipe_path = (
                engine.store.challenge_paths(case.identity).root
                / recipe_relative
            )
            recipe_path.parent.mkdir(parents=True, exist_ok=True)
            recipe_path.write_bytes(recipe_payload)
            recipe_path.chmod(0o400)

            def add_recipe(state):
                state.artifacts.append(
                    ArtifactReference(
                        id=recipe_id,
                        path=recipe_relative,
                        sha256=recipe_sha256,
                        source_run_id=builder_run_id,
                        size=len(recipe_payload),
                        extra={
                            "reported_locator": (
                                "transcript/recipe.json"
                            )
                        },
                    )
                )

            engine.store.update(case.identity, add_recipe)
            phases = (
                ("positive", 1),
                ("positive", 2),
                ("positive", 3),
                ("control", 1),
                ("control", 2),
                ("control", 3),
            )
            attempt_id = "data-transcript-process-death"
            reservation = {
                "attempt_id": attempt_id,
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "configuration_epoch": engine.store.load(
                    case.identity
                ).configuration_epoch,
                "contract_fingerprint": (
                    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
                ),
                "image_digest": engine.config.runtime.image_digest,
                "managed_builder_run_id": builder_run_id,
                "managed_experiment_id": experiment_id,
                "oracle_preissue_id": record["preissue_id"],
                "oracle_preissue_sha256": record[
                    "oracle_seal_sha256"
                ],
                "protocol": DATA_TRANSCRIPT_HOTPATH_PROTOCOL,
                "recipe_artifact_id": recipe_id,
                "recipe_sha256": recipe_sha256,
                "recipe_size_bytes": len(recipe_payload),
                "reset_commitment_sha256": record[
                    "reset_commitment_sha256"
                ],
                "replays": [
                    {
                        "artifact_ids": [
                            f"A-process-death-{position}-{index}"
                            for index in range(6)
                        ],
                        "ordinal": ordinal,
                        "phase": phase,
                        "run_id": (
                            f"data-transcript-process-death-{position}"
                        ),
                        "sidecar_artifact_ids": {
                            "request": (
                                f"A-process-death-request-{position}"
                            ),
                            "result": (
                                f"A-process-death-result-{position}"
                            ),
                            "validation": (
                                f"A-process-death-validation-{position}"
                            ),
                        },
                    }
                    for position, (phase, ordinal) in enumerate(
                        phases,
                        start=1,
                    )
                ],
                "schema_version": 1,
                "source_manifest_sha256": engine.store.load(
                    case.identity
                ).metadata["source_manifest_sha256"],
                "status": "reserved",
                "terminal": False,
            }
            engine._consume_managed_oracle_preissue(
                case.identity,
                preissue_id=str(record["preissue_id"]),
                expected_kind=(
                    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT
                ),
                builder_run_id=builder_run_id,
                experiment_id=experiment_id,
                transcript_attempt_id=attempt_id,
                transcript_reservation=reservation,
            )
            orphan_run_id = reservation["replays"][0]["run_id"]
            orphan_paths = engine.store.create_run(
                case.identity,
                run_id=orphan_run_id,
                request={"kind": "crash_left_transcript"},
                base_revision=engine.store.load(
                    case.identity
                ).revision,
            )
            self.assertTrue(orphan_paths.root.is_dir())

            recovered = engine._recover_session_boundary(case.identity)
            recovered.validate()
            self.assertFalse(orphan_paths.root.exists())
            journal = recovered.extra[DATA_TRANSCRIPT_STATE_KEY][
                attempt_id
            ]
            self.assertEqual(journal["status"], "failed")
            self.assertTrue(journal["terminal"])
            experiment = next(
                item
                for item in recovered.experiments
                if item.id == experiment_id
            )
            self.assertIs(
                experiment.status,
                ExperimentStatus.FAILED,
            )
            self.assertEqual(
                recovered.extra[
                    MANAGED_ORACLE_PREISSUE_STATE_KEY
                ][record["preissue_id"]]["status"],
                "consumed",
            )
        finally:
            case.tearDown()

    def test_oracle_not_strictly_before_builder_is_rejected(self) -> None:
        for revision_delta in (0, -1):
            with self.subTest(revision_delta=revision_delta):
                case = crypto_support.CryptoEngineProofTests(
                    "test_six_clean_bound_runs_are_required_before_promotion"
                )
                case.setUp()
                try:
                    engine, sandbox = case._engine()
                    _state, record = self._preissue_crypto(
                        engine, case.identity
                    )
                    builder_run_id, experiment_id = (
                        self._seed_running_builder(
                            engine,
                            case.identity,
                            base_revision=(
                                int(record["issue_revision"])
                                + revision_delta
                            ),
                        )
                    )
                    with self.assertRaisesRegex(
                        EngineError,
                        "not issued before",
                    ):
                        engine.prove_crypto_metamorphic_candidate(
                            case.identity,
                            "C-crypto-candidate",
                            solver_locator="solver.py",
                            original_parameters_locator="original.json",
                            oracle_preissue_id=str(
                                record["preissue_id"]
                            ),
                            _session_owned=True,
                            _managed_builder_run_id=builder_run_id,
                            _managed_experiment_id=experiment_id,
                        )
                    self.assertEqual(sandbox.proof_calls, [])
                    self.assertEqual(
                        engine.store.load(case.identity).extra[
                            MANAGED_ORACLE_PREISSUE_STATE_KEY
                        ][record["preissue_id"]]["status"],
                        "unused",
                    )
                finally:
                    case.tearDown()

    def test_current_pin_drift_rejects_before_crypto_proof_call(self) -> None:
        for drift in ("image", "configuration_epoch", "source_manifest"):
            with self.subTest(drift=drift):
                case = crypto_support.CryptoEngineProofTests(
                    "test_six_clean_bound_runs_are_required_before_promotion"
                )
                case.setUp()
                try:
                    engine, sandbox = case._engine()
                    _state, record = self._preissue_crypto(
                        engine,
                        case.identity,
                    )
                    builder_run_id, experiment_id = (
                        self._seed_running_builder(
                            engine,
                            case.identity,
                        )
                    )
                    if drift == "image":
                        engine.config = replace(
                            engine.config,
                            runtime=replace(
                                engine.config.runtime,
                                image_digest="sha256:" + "9" * 64,
                            ),
                        )
                    elif drift == "configuration_epoch":
                        def bump(state):
                            state.configuration_epoch += 1

                        engine.store.update(case.identity, bump)
                    else:
                        (
                            engine.challenge_input(case.identity)
                            / "task.py"
                        ).write_text(
                            "N = 99991\n",
                            encoding="utf-8",
                        )
                    with self.assertRaises(EngineError):
                        engine.prove_crypto_metamorphic_candidate(
                            case.identity,
                            "C-crypto-candidate",
                            solver_locator="solver.py",
                            original_parameters_locator="original.json",
                            oracle_preissue_id=str(
                                record["preissue_id"]
                            ),
                            _session_owned=True,
                            _managed_builder_run_id=builder_run_id,
                            _managed_experiment_id=experiment_id,
                        )
                    self.assertEqual(sandbox.proof_calls, [])
                finally:
                    case.tearDown()

    def test_managed_misc_always_zero_verifier_fails_negative_control(
        self,
    ) -> None:
        case = misc_support.MiscEngineTests(
            "test_clean_dag_and_three_verifier_replays_remain_candidate_only"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            original_run_clean = sandbox.run_clean_proof

            def always_zero(*args, **kwargs):
                result = original_run_clean(*args, **kwargs)
                copied = sandbox.proof_calls[-1][1]
                candidate = copied.get("candidate/candidate.bin", b"")
                if candidate.startswith(
                    b"ctfos-managed-misc-negative-v1\x00"
                ):
                    return replace(result, exit_code=0)
                return result

            sandbox.run_clean_proof = always_zero
            workspace = engine._workspace(
                engine.store.load(case.identity)
            )
            full_spec = json.loads(
                (workspace / "misc-spec.json").read_text(
                    encoding="utf-8"
                )
            )
            full_spec.pop("verifier")
            with tempfile.TemporaryDirectory() as operator_temp:
                verifier = Path(operator_temp) / "verifier.py"
                verifier.write_bytes(
                    (workspace / "verify.py").read_bytes()
                )
                _state, record = engine.preissue_managed_misc_oracle(
                    case.identity,
                    verifier_path=verifier,
                    verifier_id="original-condition",
                    oracle_id="operator-oracle-v1",
                )
            action = {
                "kind": "evaluate_misc_transform",
                "description": "hidden original-condition verifier",
                "candidate_id": "C-misc",
                "spec_artifact_path": "misc-spec.json",
                "oracle_preissue_id": record["preissue_id"],
            }
            payloads = {
                "misc-spec.json": json.dumps(
                    full_spec,
                    sort_keys=True,
                ).encode("utf-8"),
                "transform.py": (workspace / "transform.py").read_bytes(),
            }
            for locator in (
                "misc-spec.json",
                "transform.py",
                "verify.py",
            ):
                (workspace / locator).unlink()

            final, experiment, _executor = _execute_full_managed_cycle(
                engine,
                case.identity,
                action=action,
                payloads=payloads,
                extra_write_locators=("transform.py",),
            )
            candidate = next(
                item for item in final.candidates if item.id == "C-misc"
            )
            binding = candidate.extra["misc_transform_evidence"]
            self.assertFalse(binding["passed"])
            self.assertFalse(
                binding["oracle_negative_control_passed"]
            )
            self.assertEqual(len(binding["oracle_control_run_ids"]), 1)
            self.assertEqual(len(sandbox.proof_calls), 2)
            self.assertIs(
                candidate.status,
                CandidateStatus.OBSERVED_CANDIDATE,
            )
            self.assertFalse(experiment.result["passed"])
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_misc_transform_failure_commits_control_not_run_diagnostics(
        self,
    ) -> None:
        case = misc_support.MiscEngineTests(
            "test_clean_dag_and_three_verifier_replays_remain_candidate_only"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            original_run_clean = sandbox.run_clean_proof

            def fail_transform(*args, **kwargs):
                result = original_run_clean(*args, **kwargs)
                if result and args[0].argv[1] == "/work/tool/transform.py":
                    return replace(result, exit_code=17)
                return result

            sandbox.run_clean_proof = fail_transform
            workspace = engine._workspace(engine.store.load(case.identity))
            raw_spec = json.loads(
                (workspace / "misc-spec.json").read_text(encoding="utf-8")
            )
            raw_spec.pop("verifier")
            with tempfile.TemporaryDirectory() as operator_temp:
                verifier = Path(operator_temp) / "verifier.py"
                verifier.write_bytes((workspace / "verify.py").read_bytes())
                _state, record = engine.preissue_managed_misc_oracle(
                    case.identity,
                    verifier_path=verifier,
                    verifier_id="original-condition",
                    oracle_id="operator-oracle-v1",
                )
            action = {
                "kind": "evaluate_misc_transform",
                "description": "record a failed transform before the oracle",
                "candidate_id": "C-misc",
                "spec_artifact_path": "misc-spec.json",
                "oracle_preissue_id": record["preissue_id"],
            }
            payloads = {
                "misc-spec.json": json.dumps(
                    raw_spec,
                    sort_keys=True,
                ).encode("utf-8"),
                "transform.py": (workspace / "transform.py").read_bytes(),
            }
            for locator in ("misc-spec.json", "transform.py", "verify.py"):
                (workspace / locator).unlink()

            final, experiment, _executor = _execute_full_managed_cycle(
                engine,
                case.identity,
                action=action,
                payloads=payloads,
                extra_write_locators=("transform.py",),
            )
            candidate = next(
                item for item in final.candidates if item.id == "C-misc"
            )
            binding = candidate.extra["misc_transform_evidence"]
            self.assertFalse(binding["passed"])
            self.assertEqual(binding["oracle_control_status"], "not_run")
            self.assertEqual(binding["oracle_control_run_ids"], [])
            self.assertFalse(binding["oracle_negative_control_passed"])
            self.assertEqual(len(sandbox.proof_calls), 1)
            self.assertTrue(binding["evaluation"]["failure_codes"])
            self.assertFalse(experiment.result["passed"])
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_managed_crypto_streams_and_private_residue_are_not_exposed(
        self,
    ) -> None:
        case = crypto_support.CryptoEngineProofTests(
            "test_six_clean_bound_runs_are_required_before_promotion"
        )
        case.setUp()
        retained_workspaces: list[
            tuple[tempfile.TemporaryDirectory[str], Callable[[], None]]
        ] = []
        try:
            engine, _sandbox = case._engine()
            workspace = engine._workspace(engine.store.load(case.identity))
            payloads = {
                "solver.py": (workspace / "solver.py").read_bytes(),
                "original.json": (workspace / "original.json").read_bytes(),
            }
            with tempfile.TemporaryDirectory() as operator_temp:
                operator_root = Path(operator_temp)
                variant = operator_root / "hidden-variant.json"
                expected = operator_root / "hidden-expected.bin"
                variant.write_bytes((workspace / "variant.json").read_bytes())
                expected.write_bytes((workspace / "variant.out").read_bytes())
                forbidden_host_paths = (str(variant), str(expected))
                _state, record = engine.preissue_managed_crypto_oracle(
                    case.identity,
                    variant_parameters_path=variant,
                    variant_expected_output_path=expected,
                    mutation_id="private-stream-residue",
                )
            for locator in (
                "solver.py",
                "original.json",
                "variant.json",
                "variant.out",
            ):
                (workspace / locator).unlink()
            real_open = engine._open_managed_oracle_proof_workspace

            def retain_private_workspace(state):
                temporary, private = real_open(state)
                retained_workspaces.append((temporary, temporary.cleanup))
                temporary.cleanup = lambda: None
                return temporary, private

            action = {
                "kind": "prove_crypto_metamorphic",
                "description": "prove with a hidden changed-parameter oracle",
                "candidate_id": "C-crypto-candidate",
                "solver_artifact_path": "solver.py",
                "original_parameters_artifact_path": "original.json",
                "oracle_preissue_id": record["preissue_id"],
                "runtime": "python",
            }
            with mock.patch.object(
                engine,
                "_open_managed_oracle_proof_workspace",
                side_effect=retain_private_workspace,
            ):
                final, _experiment, _executor = _execute_full_managed_cycle(
                    engine,
                    case.identity,
                    action=action,
                    payloads=payloads,
                )

            streams = [
                item
                for item in final.artifacts
                if item.extra.get("kind") == "crypto_metamorphic_stream"
            ]
            self.assertEqual(len(streams), 12)
            self.assertTrue(
                all(
                    item.extra.get("context_visibility")
                    == "engine_private"
                    for item in streams
                )
            )
            private_root = (
                engine.store.challenge_paths(case.identity).runtime
                / "engine-private-managed-oracle-proof"
            )
            residue_files = [
                path for path in private_root.rglob("*") if path.is_file()
            ]
            self.assertTrue(residue_files)
            builder_roots = [
                workspace,
                *(
                    path
                    for path in engine.store.challenge_paths(
                        case.identity
                    ).runtime.glob("staging/**/work")
                    if path.is_dir()
                ),
            ]
            hidden_output = crypto_support.VARIANT_OUTPUT
            self.assertTrue(
                any(path.read_bytes() == hidden_output for path in residue_files)
            )
            self.assertFalse(
                any(
                    path.read_bytes() == hidden_output
                    for root in builder_roots
                    for path in root.rglob("*")
                    if path.is_file()
                )
            )
            pack = build_context_pack(
                final,
                get_adapter(final.category),
                state_path=engine.store.challenge_paths(case.identity).state,
                role=Role.BUILDER.value,
            ).text
            broker = json.dumps(
                inspect_state(final, "state"),
                sort_keys=True,
            )
            for forbidden in (
                *forbidden_host_paths,
                hidden_output.decode("utf-8").strip(),
            ):
                self.assertNotIn(forbidden, pack)
                self.assertNotIn(forbidden, broker)
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            for _temporary, cleanup in retained_workspaces:
                cleanup()
            case.tearDown()

    def test_managed_misc_verifier_stream_marker_is_not_exposed(
        self,
    ) -> None:
        case = misc_support.MiscEngineTests(
            "test_clean_dag_and_three_verifier_replays_remain_candidate_only"
        )
        case.setUp()
        try:
            engine, sandbox = case._engine()
            marker = b"hidden-verifier-source-marker-4d89"
            original_run_clean = sandbox.run_clean_proof

            def leak_verifier_marker(*args, **kwargs):
                result = original_run_clean(*args, **kwargs)
                if args[0].argv[1] != "/work/oracle/verifier.py":
                    return result
                stderr = (
                    sandbox.work
                    / result.stderr_path.removeprefix("/work/").lstrip("/")
                )
                stderr.write_bytes(marker)
                return replace(
                    result,
                    stderr_summary=marker.decode("ascii"),
                    stderr_bytes=len(marker),
                    stderr_stored_bytes=len(marker),
                )

            sandbox.run_clean_proof = leak_verifier_marker
            workspace = engine._workspace(engine.store.load(case.identity))
            raw_spec = json.loads(
                (workspace / "misc-spec.json").read_text(encoding="utf-8")
            )
            raw_spec.pop("verifier")
            with tempfile.TemporaryDirectory() as operator_temp:
                verifier = Path(operator_temp) / "hidden-verifier.py"
                verifier.write_bytes(
                    (workspace / "verify.py").read_bytes()
                    + b"\n# "
                    + marker
                    + b"\n"
                )
                forbidden_host_path = str(verifier)
                _state, record = engine.preissue_managed_misc_oracle(
                    case.identity,
                    verifier_path=verifier,
                    verifier_id="original-condition",
                    oracle_id="operator-oracle-v1",
                )
            action = {
                "kind": "evaluate_misc_transform",
                "description": "hide verifier output while preserving verdicts",
                "candidate_id": "C-misc",
                "spec_artifact_path": "misc-spec.json",
                "oracle_preissue_id": record["preissue_id"],
            }
            payloads = {
                "misc-spec.json": json.dumps(
                    raw_spec,
                    sort_keys=True,
                ).encode("utf-8"),
                "transform.py": (workspace / "transform.py").read_bytes(),
            }
            for locator in ("misc-spec.json", "transform.py", "verify.py"):
                (workspace / locator).unlink()

            final, _experiment, _executor = _execute_full_managed_cycle(
                engine,
                case.identity,
                action=action,
                payloads=payloads,
                extra_write_locators=("transform.py",),
            )
            verifier_streams = [
                item
                for item in final.artifacts
                if item.extra.get("kind") == "misc_transform_stream"
                and item.extra.get("phase") in {"oracle-control", "reverse"}
            ]
            self.assertEqual(len(verifier_streams), 8)
            self.assertTrue(
                all(
                    item.extra.get("context_visibility")
                    == "engine_private"
                    for item in verifier_streams
                )
            )
            pack = build_context_pack(
                final,
                get_adapter(final.category),
                state_path=engine.store.challenge_paths(case.identity).state,
                role=Role.BUILDER.value,
            ).text
            broker = json.dumps(
                inspect_state(final, "state"),
                sort_keys=True,
            )
            for forbidden in (
                marker.decode("ascii"),
                forbidden_host_path,
            ):
                self.assertNotIn(forbidden, pack)
                self.assertNotIn(forbidden, broker)
            self.assertEqual(final.submissions, [])
            final.validate()
        finally:
            case.tearDown()

    def test_preissue_cli_routes_only_public_identifiers(self) -> None:
        root = Path(self.temporary.name)
        identity = crypto_support.ChallengeIdentity(
            "CLI CTF",
            "crypto",
            "hidden",
        )
        record = {
            "schema_version": 1,
            "protocol": "managed_oracle_preissue_v1",
            "preissue_id": "oracle-preissue-cli",
            "kind": "crypto",
            "status": "unused",
            "issuer": "operator",
            "issued_at": "2026-07-31T00:00:00Z",
            "issue_revision": 3,
            "configuration_epoch": 1,
            "source_manifest_sha256": "a" * 64,
            "image_digest": "sha256:" + "b" * 64,
            "oracle_seal_sha256": "c" * 64,
            "consumed_at": None,
            "consumed_by_builder_run_id": None,
            "consumed_by_experiment_id": None,
        }
        state = mock.Mock(revision=3)
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "managed-oracle-preissue-crypto",
            identity.contest_id,
            identity.category,
            identity.challenge_id,
            "--variant-parameters",
            "operator/variant.json",
            "--variant-expected-output",
            "operator/expected.bin",
            "--mutation-id",
            "variant-cli",
        ]
        with (
            mock.patch.object(
                ChallengeEngine,
                "preissue_managed_crypto_oracle",
                return_value=(state, record),
            ) as preissue,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main(arguments, root=root)

        self.assertEqual(status, 0, stderr.getvalue())
        preissue.assert_called_once_with(
            identity,
            variant_parameters_path="operator/variant.json",
            variant_expected_output_path="operator/expected.bin",
            mutation_id="variant-cli",
        )
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["preissue_id"], "oracle-preissue-cli")
        self.assertNotIn("variant_parameters", output)
        self.assertNotIn("variant_expected_output", output)
        self.assertNotIn("path", json.dumps(output))

    def test_transcript_preissue_cli_routes_only_public_record(self) -> None:
        root = Path(self.temporary.name)
        identity = crypto_support.ChallengeIdentity(
            "CLI CTF",
            "crypto",
            "transcript",
        )
        record = {
            "schema_version": 1,
            "protocol": "managed_oracle_preissue_v1",
            "preissue_id": "oracle-transcript-cli",
            "kind": "crypto_transcript",
            "status": "unused",
            "issuer": "operator",
            "issued_at": "2026-07-31T00:00:00Z",
            "issue_revision": 4,
            "configuration_epoch": 1,
            "source_manifest_sha256": "a" * 64,
            "image_digest": "sha256:" + "b" * 64,
            "oracle_seal_sha256": "c" * 64,
            "reset_commitment_sha256": "d" * 64,
            "consumed_at": None,
            "consumed_by_builder_run_id": None,
            "consumed_by_experiment_id": None,
        }
        state = mock.Mock(revision=4)
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "managed-oracle-preissue-crypto-transcript",
            identity.contest_id,
            identity.category,
            identity.challenge_id,
            "--peer",
            "operator/peer.py",
            "--peer-data",
            "operator/seed.bin",
        ]
        with (
            mock.patch.object(
                ChallengeEngine,
                "preissue_managed_crypto_transcript",
                return_value=(state, record),
            ) as preissue,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main(arguments, root=root)

        self.assertEqual(status, 0, stderr.getvalue())
        preissue.assert_called_once_with(
            identity,
            peer_path="operator/peer.py",
            peer_data_path="operator/seed.bin",
        )
        output = json.loads(stdout.getvalue())
        self.assertEqual(
            output["preissue_id"],
            "oracle-transcript-cli",
        )
        self.assertEqual(output["state_revision"], 4)
        self.assertNotIn("operator/peer.py", json.dumps(output))
        self.assertNotIn("operator/seed.bin", json.dumps(output))
        self.assertNotIn("inputs", output)


if __name__ == "__main__":
    unittest.main()
