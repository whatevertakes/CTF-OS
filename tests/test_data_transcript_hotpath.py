from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_CONTRACT_ID,
    DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
    DATA_TRANSCRIPT_V1_PROTOCOL,
    data_transcript_v1_canonical_json_bytes,
    data_transcript_v1_reset_commitment_sha256,
)
from ctf_os.codex import Role
from ctf_os.engine.data_transcript import (
    DataTranscriptEvaluation,
    DataTranscriptReplayReceipt,
)
from ctf_os.engine.data_transcript_hotpath import (
    DATA_TRANSCRIPT_PRODUCER_PATH,
    DATA_TRANSCRIPT_PRODUCER_SHA256,
    DATA_TRANSCRIPT_STATE_KEY,
    DataTranscriptHotPathError,
    prove_data_transcript,
    recover_data_transcript_attempts,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
    ManagedOraclePreissueInput,
    build_manifest,
    public_record,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    ModelValidationError,
    ProofRecipeInput,
    RunOrigin,
    RunReference,
    RunStatus,
    utc_now,
)
from ctf_os.sandbox import (
    ArtifactRef,
    NetworkPolicy,
    SandboxResult,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import (
    ArtifactValidationError,
    RevisionConflict,
    StateStore,
)


IMAGE_DIGEST = "sha256:" + "a" * 64
SOURCE_MANIFEST = "b" * 64
SCOPE = "c" * 64
BUILDER_RUN_ID = "builder-run"
EXPERIMENT_ID = "typed-gate-experiment"
PREISSUE_ID = "operator-transcript-preissue"
RECIPE_LOCATOR = "builder/recipe.json"
RECIPE_ARTIFACT_ID = "builder-recipe-artifact"
RAW_SECRET = b"RAW-ORACLE-STREAM-MUST-NOT-ENTER-STATE"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _recipe(reset_commitment: str) -> bytes:
    return data_transcript_v1_canonical_json_bytes(
        {
            "category": "crypto",
            "contract": {
                "id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
                "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
                "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
            },
            "preissue_id": PREISSUE_ID,
            "reset_commitment_sha256": reset_commitment,
            "schema_version": 1,
            "steps": [
                {
                    "data": {"encoding": "hex", "value": "01"},
                    "id": "send",
                    "op": "send",
                },
                {
                    "data": {"encoding": "utf8", "value": "ok\n"},
                    "id": "expect",
                    "max_read_bytes": 3,
                    "op": "expect",
                    "stream": "stdout",
                },
            ],
            "timeout_milliseconds": 1000,
        }
    )


class _Paths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.runtime = root / "runtime"
        self.artifacts = root / "artifacts"
        self.proof = root / "proof"
        self.runs = root / "runs"
        for path in (
            self.runtime,
            self.artifacts,
            self.proof,
            self.runs,
        ):
            path.mkdir(parents=True, exist_ok=True)


class _Store:
    def __init__(self, root: Path, state: ChallengeState) -> None:
        self.paths = _Paths(root)
        self.state = copy.deepcopy(state)
        self.max_artifact_bytes = 1024 * 1024 * 1024
        self.create_run_calls = 0
        self.create_run_fail_at: int | None = None
        self.fail_preissue_publish_once = False

    def challenge_paths(self, _identity):
        return self.paths

    def load(self, _identity, recover=True):
        del recover
        return copy.deepcopy(self.state)

    def update(
        self,
        _identity,
        mutator,
        *,
        expected_revision=None,
        commit_guard=None,
        pre_replace_guard=None,
    ):
        if expected_revision is not None:
            if self.state.revision != expected_revision:
                raise RevisionConflict(
                    expected_revision,
                    self.state.revision,
                )
        if commit_guard is not None:
            commit_guard()
        candidate = copy.deepcopy(self.state)
        mutator(candidate)
        candidate.validate()
        if (
            self.fail_preissue_publish_once
            and getattr(mutator, "__name__", "") == "add_preissue"
        ):
            self.fail_preissue_publish_once = False
            expected = self.state.revision
            self.state.revision += 1
            raise RevisionConflict(expected, self.state.revision)
        if pre_replace_guard is not None:
            pre_replace_guard()
        candidate.revision = self.state.revision + 1
        self.state = candidate
        return copy.deepcopy(candidate)

    def _run_paths(self, run_id: str):
        root = self.paths.runs / run_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "raw").mkdir(exist_ok=True)
        return SimpleNamespace(
            root=root,
            request=root / "request.json",
            result=root / "result.json",
            validation=root / "validation.json",
        )

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.write_bytes(
            (
                json.dumps(
                    value,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        )

    def create_run(
        self,
        _identity,
        run_id,
        *,
        request,
        base_revision,
    ):
        del base_revision
        paths = self._run_paths(run_id)
        self.create_run_calls += 1
        self._write(paths.request, request)
        if self.create_run_calls == self.create_run_fail_at:
            raise OSError("injected create_run failure")
        return paths

    def write_run_result(self, _identity, run_id, value):
        self._write(self._run_paths(run_id).result, value)

    def write_run_validation(self, _identity, run_id, value):
        self._write(self._run_paths(run_id).validation, value)

    def run_paths(self, _identity, run_id):
        return self._run_paths(run_id)


class _Lease:
    def __init__(self) -> None:
        self.released = False

    def release(self) -> None:
        self.released = True


class _LeaseBroker:
    def __init__(self) -> None:
        self.leases: list[_Lease] = []

    def acquire(self, request, *, timeout, owner):
        assert request.network == 0
        assert timeout == 30.0
        assert owner
        lease = _Lease()
        self.leases.append(lease)
        return lease


class _Sandbox:
    def __init__(
        self,
        workspace: Path,
        events: list[str],
        *,
        incomplete: bool = False,
        reuse_identity: bool = False,
        on_run=None,
    ) -> None:
        self.workspace = workspace
        self.events = events
        self.incomplete = incomplete
        self.reuse_identity = reuse_identity
        self.on_run = on_run
        self.scope_fingerprint = SCOPE
        self.calls: list[tuple[object, tuple, tuple]] = []
        self.counter = 0

    def _artifact(self, locator: str) -> ArtifactRef:
        payload = (self.workspace / locator).read_bytes()
        return ArtifactRef(
            locator=locator,
            sha256=_sha(payload),
            size_bytes=len(payload),
            scope_fingerprint=SCOPE,
        )

    def run_clean_proof(
        self,
        command,
        *,
        proof_inputs=(),
        proof_outputs=(),
    ):
        self.events.append("run")
        self.calls.append(
            (command, tuple(proof_inputs), tuple(proof_outputs))
        )
        self.counter += 1
        if self.on_run is not None:
            self.on_run(self.counter)
        identity_index = 1 if self.reuse_identity else self.counter
        prefix = f"clean-{identity_index:012x}"
        sandbox_run_id = f"sandbox-{identity_index}"
        clean = self.workspace / "proof" / prefix
        outputs = clean / "outputs"
        outputs.mkdir(parents=True, exist_ok=self.reuse_identity)
        document = f"producer-document-{self.counter}\n".encode("ascii")
        producer_stderr = b""
        (clean / "stdout.log").write_bytes(document)
        (clean / "stderr.log").write_bytes(producer_stderr)
        output_payloads = (
            RAW_SECRET,
            b"",
            b'{"transcript":"private"}\n',
            b'{"reset":"private"}\n',
        )
        for declaration, payload in zip(
            proof_outputs, output_payloads, strict=True
        ):
            (outputs / declaration.name).write_bytes(payload)
        refs = tuple(
            self._artifact(f"proof/{prefix}/outputs/{item.name}")
            for item in proof_outputs
        )
        complete = not (self.incomplete and self.counter == 1)
        return SandboxResult(
            run_id=sandbox_run_id,
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary="producer",
            stderr_summary="",
            stdout_bytes=len(document),
            stderr_bytes=0,
            stdout_path=f"/work/proof/{prefix}/stdout.log",
            stderr_path=f"/work/proof/{prefix}/stderr.log",
            stdout_stored_bytes=len(document),
            stderr_stored_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=complete,
            stderr_capture_complete=True,
            proof_outputs=refs,
        )

    def register_artifact(self, locator, *, maximum_bytes):
        payload = (self.workspace / locator).read_bytes()
        assert len(payload) <= maximum_bytes
        return self._artifact(locator)


class _Engine:
    def __init__(
        self,
        root: Path,
        state: ChallengeState,
        manifest,
        peer_artifact: ArtifactReference,
        peer_data_artifact: ArtifactReference,
        *,
        incomplete: bool = False,
        reuse_identity: bool = False,
        image_drift_after_first: bool = False,
        revision_drift_after_first: bool = False,
        mutate_recipe_on_probe: bool = False,
        create_run_fail_at: int | None = None,
        fail_preissue_publish_once: bool = False,
        reject_exact_admission_at: int | None = None,
    ) -> None:
        self.store = _Store(root, state)
        self.store.create_run_fail_at = create_run_fail_at
        self.store.fail_preissue_publish_once = (
            fail_preissue_publish_once
        )
        self.manifest = manifest
        self.peer_artifact = peer_artifact
        self.peer_data_artifact = peer_data_artifact
        self.config = SimpleNamespace(
            runtime=SimpleNamespace(image_digest=IMAGE_DIGEST)
        )
        self._capability_probe_accepts_timeout = False
        self.lease_broker = _LeaseBroker()
        self.events: list[str] = []
        self.storage_admissions: list[int | None] = []
        self.sandbox_client: _Sandbox | None = None
        self.incoming = root / "incoming"
        self.incoming.mkdir()
        (self.incoming / "challenge.txt").write_text(
            "immutable input", encoding="utf-8"
        )

        self.incomplete = incomplete
        self.reuse_identity = reuse_identity
        self.image_drift_after_first = image_drift_after_first
        self.revision_drift_after_first = revision_drift_after_first
        self.mutate_recipe_on_probe = mutate_recipe_on_probe
        self.probe_calls = 0
        self.reject_exact_admission_at = reject_exact_admission_at
        self.exact_admission_calls = 0

    def _enforce_storage_admission(
        self,
        _identity,
        *,
        requested_bytes: int | None = None,
    ):
        self.storage_admissions.append(requested_bytes)
        if requested_bytes is not None:
            self.exact_admission_calls += 1
            if (
                self.reject_exact_admission_at
                == self.exact_admission_calls
            ):
                raise RuntimeError("challenge storage quota exceeded")
        return {}

    def refresh_ingest(self, identity):
        return self.store.load(identity)

    def challenge_input(self, _identity):
        return self.incoming

    def _capability_probe(self, image_digest):
        self.events.append("probe")
        self.probe_calls += 1
        if self.mutate_recipe_on_probe and self.probe_calls == 1:
            recipe_path = (
                self.store.paths.artifacts
                / "workspace"
                / RECIPE_LOCATOR
            )
            recipe_path.write_bytes(
                _recipe(self.manifest.metadata[
                    "reset_commitment_sha256"
                ])
                + b" "
            )
        return {
            "attestation_errors": {},
            "attestations": {
                "data_transcript_v1": copy.deepcopy(
                    REQUIRED_MANAGED_ATTESTATIONS[
                        "data_transcript_v1"
                    ]
                )
            },
            "available": ["data_transcript_v1"],
            "image_digest": image_digest,
            "ok": True,
        }

    def register_workspace_artifact(
        self,
        identity,
        locator,
        *,
        source_run_id,
        _live_only,
    ):
        assert _live_only is True
        self.events.append("register")
        source = (
            self.store.paths.artifacts / "workspace" / locator
        )
        payload = source.read_bytes()
        destination = (
            self.store.paths.artifacts
            / "snapshots"
            / "recipe.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        artifact = ArtifactReference(
            id="recipe-artifact",
            path=destination.relative_to(
                self.store.paths.root
            ).as_posix(),
            sha256=_sha(payload),
            size=len(payload),
            source_run_id=source_run_id,
            extra={"source_locator": locator},
        )

        def add(current):
            current.artifacts.append(copy.deepcopy(artifact))

        result = self.store.update(identity, add)
        return result, artifact

    def _consume_managed_oracle_preissue(
        self,
        identity,
        *,
        preissue_id,
        expected_kind,
        builder_run_id,
        experiment_id,
        transcript_attempt_id=None,
        transcript_reservation=None,
    ):
        self.events.append("consume")
        assert preissue_id == PREISSUE_ID
        assert expected_kind == MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT
        assert builder_run_id == BUILDER_RUN_ID
        assert experiment_id == EXPERIMENT_ID
        assert type(transcript_attempt_id) is str
        assert type(transcript_reservation) is dict
        assert (
            transcript_reservation["attempt_id"]
            == transcript_attempt_id
        )

        def consume(current):
            record = copy.deepcopy(
                current.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
                    PREISSUE_ID
                ]
            )
            record.update(
                {
                    "consumed_at": utc_now(),
                    "consumed_by_builder_run_id": BUILDER_RUN_ID,
                    "consumed_by_experiment_id": EXPERIMENT_ID,
                    "status": "consumed",
                }
            )
            current.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
                PREISSUE_ID
            ] = record
            history = copy.deepcopy(
                current.extra.get(DATA_TRANSCRIPT_STATE_KEY, {})
            )
            history[transcript_attempt_id] = copy.deepcopy(
                transcript_reservation
            )
            current.extra[DATA_TRANSCRIPT_STATE_KEY] = history

        self.store.update(identity, consume)
        bindings = (
            (
                copy.deepcopy(self.peer_artifact),
                ProofRecipeInput(
                    artifact_id=self.peer_artifact.id,
                    destination="oracle/peer",
                    purpose="transcript_peer",
                    sha256=self.peer_artifact.sha256,
                    size=int(self.peer_artifact.size or 0),
                    source_run_id=None,
                ),
            ),
            (
                copy.deepcopy(self.peer_data_artifact),
                ProofRecipeInput(
                    artifact_id=self.peer_data_artifact.id,
                    destination="oracle/peer-data.bin",
                    purpose="transcript_peer_data",
                    sha256=self.peer_data_artifact.sha256,
                    size=int(self.peer_data_artifact.size or 0),
                    source_run_id=None,
                ),
            ),
        )
        return SimpleNamespace(
            manifest=self.manifest,
            bindings=bindings,
        )

    def _open_managed_oracle_proof_workspace(self, _state):
        temporary = tempfile.TemporaryDirectory(
            dir=self.store.paths.runtime
        )
        return temporary, Path(temporary.name)

    def sandbox(
        self,
        _state,
        *,
        workspace_override,
        challenge_dir_override,
        network_policy_override,
    ):
        self.events.append("sandbox")
        assert challenge_dir_override.parent == workspace_override
        assert network_policy_override == NetworkPolicy.deny_all()
        self.sandbox_client = _Sandbox(
            workspace_override,
            self.events,
            incomplete=self.incomplete,
            reuse_identity=self.reuse_identity,
            on_run=(
                self._on_run
            ),
        )
        return self.sandbox_client

    def _on_run(self, count: int) -> None:
        if self.image_drift_after_first and count == 1:
            self.config.runtime.image_digest = (
                "sha256:" + "e" * 64
            )
        if self.revision_drift_after_first and count == 1:
            def drift(current):
                current.extra["injected_revision_drift"] = True

            self.store.update(
                ChallengeIdentity(
                    "contest",
                    self.store.state.category,
                    "interactive",
                ),
                drift,
            )

    def _cleanup_uncommitted_artifacts(
        self, _identity, artifacts, *, cause
    ):
        del cause
        for artifact in artifacts:
            path = self.store.paths.root / artifact.path
            path.chmod(0o600)
            path.unlink()


def _evaluation(expected_binding):
    def receipt(phase: str, ordinal: int):
        return DataTranscriptReplayReceipt(
            phase=phase,
            ordinal=ordinal,
            status="matched" if phase == "positive" else "rejected",
            reason_code=(
                "all_steps_matched"
                if phase == "positive"
                else "control_mutation_rejected"
            ),
            fresh_instance_nonce_sha256=(
                f"{ordinal if phase == 'positive' else ordinal + 3:064x}"
            ),
            stdout_sha256="1" * 64,
            stderr_sha256="2" * 64,
            transcript_sha256="3" * 64,
            reset_proof_sha256="4" * 64,
            mismatch_step_id=None if phase == "positive" else "expect",
        )

    return DataTranscriptEvaluation(
        passed=True,
        reason_code="validated_three_clean_three_negative_replays",
        reset_commitment_sha256=(
            expected_binding.reset_commitment_sha256
        ),
        positive_receipts=tuple(
            receipt("positive", ordinal) for ordinal in (1, 2, 3)
        ),
        control_receipts=tuple(
            receipt("control", ordinal) for ordinal in (1, 2, 3)
        ),
    )


class DataTranscriptHotPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        peer = b"#!/bin/sh\nexit 0\n"
        peer_data = b"operator-private-seed"
        peer_path = self.root / "artifacts" / "oracle" / "peer"
        data_path = self.root / "artifacts" / "oracle" / "peer-data.bin"
        peer_path.parent.mkdir(parents=True)
        peer_path.write_bytes(peer)
        peer_path.chmod(0o500)
        data_path.write_bytes(peer_data)
        data_path.chmod(0o400)
        self.peer_artifact = ArtifactReference(
            id="peer-artifact",
            path=peer_path.relative_to(self.root).as_posix(),
            sha256=_sha(peer),
            size=len(peer),
            extra={
                "context_visibility": "engine_private",
                "kind": "managed_oracle_preissue_input",
                "preissue_id": PREISSUE_ID,
                "protocol": "managed_oracle_preissue_v1",
                "purpose": "transcript_peer",
            },
        )
        self.peer_data_artifact = ArtifactReference(
            id="peer-data-artifact",
            path=data_path.relative_to(self.root).as_posix(),
            sha256=_sha(peer_data),
            size=len(peer_data),
            extra={
                "context_visibility": "engine_private",
                "kind": "managed_oracle_preissue_input",
                "preissue_id": PREISSUE_ID,
                "protocol": "managed_oracle_preissue_v1",
                "purpose": "transcript_peer_data",
            },
        )
        self.reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=self.peer_artifact.sha256,
            peer_size_bytes=int(self.peer_artifact.size or 0),
            peer_data_sha256=self.peer_data_artifact.sha256,
            peer_data_size_bytes=int(
                self.peer_data_artifact.size or 0
            ),
        )
        self.manifest = build_manifest(
            preissue_id=PREISSUE_ID,
            kind=MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
            issued_at=utc_now(),
            issue_revision=1,
            configuration_epoch=7,
            source_manifest_sha256=SOURCE_MANIFEST,
            image_digest=IMAGE_DIGEST,
            seal_nonce="d" * 64,
            metadata={
                "reset_commitment_sha256": self.reset
            },
            inputs=(
                ManagedOraclePreissueInput(
                    purpose="transcript_peer",
                    artifact_id=self.peer_artifact.id,
                    sha256=self.peer_artifact.sha256,
                    size_bytes=int(self.peer_artifact.size or 0),
                ),
                ManagedOraclePreissueInput(
                    purpose="transcript_peer_data",
                    artifact_id=self.peer_data_artifact.id,
                    sha256=self.peer_data_artifact.sha256,
                    size_bytes=int(
                        self.peer_data_artifact.size or 0
                    ),
                ),
            ),
        )
        self.state = ChallengeState(
            contest_id="contest",
            category="crypto",
            challenge_id="interactive",
            schema_version=STATE_SCHEMA_VERSION,
            revision=10,
            status=ChallengeStatus.ACTIVE,
            metadata={
                "source_manifest_sha256": SOURCE_MANIFEST
            },
            configuration_epoch=7,
            artifacts=[
                copy.deepcopy(self.peer_artifact),
                copy.deepcopy(self.peer_data_artifact),
            ],
            runs=[
                RunReference(
                    id=BUILDER_RUN_ID,
                    base_revision=2,
                    status=RunStatus.COMPLETED,
                    role=Role.BUILDER.value,
                    origin=RunOrigin.MANAGED_MODEL,
                    request_path="runs/builder-run/request.json",
                    result_path="runs/builder-run/result.json",
                    validation_path="runs/builder-run/validation.json",
                )
            ],
            experiments=[
                Experiment(
                    id=EXPERIMENT_ID,
                    hypothesis_ids=[],
                    command="typed gate",
                    expected_observation="bounded transcript",
                    keep_if="3+3 passes",
                    drop_if="any replay fails",
                    timeout_seconds=60,
                    kind=ExperimentKind.PROBE,
                    status=ExperimentStatus.RUNNING,
                    source_run_id=BUILDER_RUN_ID,
                )
            ],
            extra={
                MANAGED_ORACLE_PREISSUE_STATE_KEY: {
                    PREISSUE_ID: public_record(self.manifest)
                }
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _engine(
        self,
        *,
        incomplete: bool = False,
        reuse_identity: bool = False,
        image_drift_after_first: bool = False,
        revision_drift_after_first: bool = False,
        mutate_recipe_on_probe: bool = False,
        create_run_fail_at: int | None = None,
        fail_preissue_publish_once: bool = False,
        reject_exact_admission_at: int | None = None,
        category: str = "crypto",
    ) -> _Engine:
        state = copy.deepcopy(self.state)
        state.category = category
        engine = _Engine(
            self.root,
            state,
            self.manifest,
            self.peer_artifact,
            self.peer_data_artifact,
            incomplete=incomplete,
            reuse_identity=reuse_identity,
            image_drift_after_first=image_drift_after_first,
            revision_drift_after_first=revision_drift_after_first,
            mutate_recipe_on_probe=mutate_recipe_on_probe,
            create_run_fail_at=create_run_fail_at,
            fail_preissue_publish_once=fail_preissue_publish_once,
            reject_exact_admission_at=reject_exact_admission_at,
        )
        recipe_bytes = _recipe(self.reset)
        recipe_snapshot = (
            engine.store.paths.artifacts
            / "snapshots"
            / "builder-recipe.json"
        )
        recipe_snapshot.parent.mkdir(parents=True, exist_ok=True)
        recipe_snapshot.write_bytes(recipe_bytes)
        recipe_snapshot.chmod(0o400)
        engine.store.state.artifacts.append(
            ArtifactReference(
                id=RECIPE_ARTIFACT_ID,
                path=recipe_snapshot.relative_to(
                    engine.store.paths.root
                ).as_posix(),
                sha256=_sha(recipe_bytes),
                size=len(recipe_bytes),
                source_run_id=BUILDER_RUN_ID,
                extra={"reported_locator": RECIPE_LOCATOR},
            )
        )
        recipe_path = (
            engine.store.paths.artifacts
            / "workspace"
            / RECIPE_LOCATOR
        )
        recipe_path.parent.mkdir(parents=True)
        recipe_path.write_bytes(recipe_bytes)
        return engine

    @staticmethod
    def _run(engine: _Engine):
        identity = ChallengeIdentity(
            contest_id="contest",
            category=engine.store.state.category,
            challenge_id="interactive",
        )

        def evaluate(evidence, *, expected_binding, recipe_bytes):
            assert len(tuple(evidence)) == 6
            assert recipe_bytes == _recipe(
                expected_binding.reset_commitment_sha256
            )
            return _evaluation(expected_binding)

        with (
            mock.patch(
                "ctf_os.engine.data_transcript_hotpath."
                "inventory_challenge",
                return_value=SimpleNamespace(
                    manifest_sha256=SOURCE_MANIFEST
                ),
            ),
            mock.patch(
                "ctf_os.engine.data_transcript_hotpath."
                "evaluate_data_transcript_replays",
                side_effect=evaluate,
            ),
        ):
            return prove_data_transcript(
                engine,
                identity,
                recipe_locator=RECIPE_LOCATOR,
                recipe_artifact_id=RECIPE_ARTIFACT_ID,
                recipe_sha256=_sha(_recipe(engine.manifest.metadata[
                    "reset_commitment_sha256"
                ])),
                recipe_size_bytes=len(
                    _recipe(engine.manifest.metadata[
                        "reset_commitment_sha256"
                    ])
                ),
                oracle_preissue_id=PREISSUE_ID,
                _session_owned=True,
                _managed_builder_run_id=BUILDER_RUN_ID,
                _managed_experiment_id=EXPERIMENT_ID,
            )

    def _reservation(self) -> dict[str, object]:
        recipe_bytes = _recipe(self.reset)
        phases = (
            ("positive", 1),
            ("positive", 2),
            ("positive", 3),
            ("control", 1),
            ("control", 2),
            ("control", 3),
        )
        return {
            "attempt_id": "data-transcript-recovery-attempt",
            "automatic_submission_authorized": False,
            "candidate_authorized": False,
            "configuration_epoch": 7,
            "contract_fingerprint": (
                DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
            ),
            "image_digest": IMAGE_DIGEST,
            "managed_builder_run_id": BUILDER_RUN_ID,
            "managed_experiment_id": EXPERIMENT_ID,
            "oracle_preissue_id": PREISSUE_ID,
            "oracle_preissue_sha256": self.manifest.sha256,
            "protocol": "ctfos.data_transcript.hotpath.v1",
            "recipe_artifact_id": RECIPE_ARTIFACT_ID,
            "recipe_sha256": _sha(recipe_bytes),
            "recipe_size_bytes": len(recipe_bytes),
            "reset_commitment_sha256": self.reset,
            "replays": [
                {
                    "artifact_ids": [
                        f"A-recovery-{position}-{index}"
                        for index in range(6)
                    ],
                    "ordinal": ordinal,
                    "phase": phase,
                    "run_id": f"data-transcript-recovery-{position}",
                    "sidecar_artifact_ids": {
                        "request": (
                            f"A-recovery-request-{position}"
                        ),
                        "result": f"A-recovery-result-{position}",
                        "validation": (
                            f"A-recovery-validation-{position}"
                        ),
                    },
                }
                for position, (phase, ordinal) in enumerate(
                    phases,
                    start=1,
                )
            ],
            "schema_version": 1,
            "source_manifest_sha256": SOURCE_MANIFEST,
            "status": "reserved",
            "terminal": False,
        }

    def test_exact_managed_command_inputs_network_and_private_state(self):
        engine = self._engine()
        final_state, evaluation = self._run(engine)

        self.assertTrue(evaluation.passed)
        final_state.validate()
        self.assertEqual(engine.events.count("consume"), 1)
        self.assertLess(
            engine.events.index("consume"),
            engine.events.index("probe"),
        )
        self.assertNotIn("register", engine.events)
        self.assertLess(
            engine.events.index("consume"),
            engine.events.index("sandbox"),
        )
        self.assertEqual(engine.events.count("run"), 6)
        self.assertEqual(engine.storage_admissions[0], None)
        self.assertIn(len(RAW_SECRET), engine.storage_admissions)
        self.assertTrue(
            all(
                value is None or value >= 0
                for value in engine.storage_admissions
            )
        )

        self.assertIsNotNone(engine.sandbox_client)
        assert engine.sandbox_client is not None
        self.assertEqual(len(engine.sandbox_client.calls), 6)
        for index, (command, inputs, outputs) in enumerate(
            engine.sandbox_client.calls
        ):
            phase = "positive" if index < 3 else "control"
            ordinal = index + 1 if index < 3 else index - 2
            self.assertEqual(
                command.argv[:2],
                (
                    "/usr/bin/python3",
                    DATA_TRANSCRIPT_PRODUCER_PATH,
                ),
            )
            self.assertNotIn("/bin/sh", command.argv)
            self.assertEqual(dict(command.environment), {})
            self.assertIsNone(command.network_target)
            self.assertEqual(command.resource_request.network, 0)
            self.assertEqual(
                command.argv[
                    command.argv.index("--producer-sha256") + 1
                ],
                DATA_TRANSCRIPT_PRODUCER_SHA256,
            )
            self.assertEqual(
                command.argv[command.argv.index("--phase") + 1],
                phase,
            )
            self.assertEqual(
                command.argv[command.argv.index("--ordinal") + 1],
                str(ordinal),
            )
            self.assertEqual(
                tuple(item.destination_locator for item in inputs),
                (
                    "bound/peer",
                    "bound/peer-data.bin",
                    "bound/recipe.json",
                ),
            )
            self.assertEqual(
                tuple(item.name for item in outputs),
                (
                    "peer.stdout.bin",
                    "peer.stderr.bin",
                    "transcript.json",
                    "reset-proof.json",
                ),
            )
        serialized = json.dumps(
            final_state.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
        )
        self.assertNotIn(RAW_SECRET.decode("ascii"), serialized)
        self.assertEqual(final_state.candidates, [])
        self.assertEqual(final_state.submissions, [])
        private_artifacts = [
            item
            for item in final_state.artifacts
            if item.extra.get("protocol")
            == "ctfos.data_transcript.hotpath.v1"
        ]
        self.assertEqual(len(private_artifacts), 55)
        self.assertTrue(
            all(
                item.extra.get("context_visibility")
                == "engine_private"
                for item in private_artifacts
            )
        )
        journals = final_state.extra[DATA_TRANSCRIPT_STATE_KEY]
        self.assertEqual(len(journals), 1)
        journal = next(iter(journals.values()))
        self.assertEqual(journal["status"], "passed")
        self.assertFalse(journal["candidate_authorized"])
        self.assertFalse(
            journal["automatic_submission_authorized"]
        )
        self.assertEqual(
            journal["unique_proof_identity_count"], 6
        )
        self.assertEqual(
            journal["unique_sandbox_run_id_count"], 6
        )
        self.assertTrue(engine.lease_broker.leases[0].released)
        experiment = next(
            item
            for item in final_state.experiments
            if item.id == EXPERIMENT_ID
        )
        self.assertIs(
            experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertTrue(experiment.result["passed"])
        self.assertEqual(
            experiment.result["evaluation_sha256"],
            journal["evaluation_sha256"],
        )

    def test_mid_capture_quota_reject_cleans_partial_artifacts(self):
        engine = self._engine(reject_exact_admission_at=6)

        with self.assertRaisesRegex(
            RuntimeError,
            "storage quota exceeded",
        ):
            self._run(engine)

        capture_files = list(
            engine.store.paths.artifacts.glob(
                "data-transcript/*/captures/*"
            )
        )
        self.assertEqual(capture_files, [])
        self.assertGreater(engine.exact_admission_calls, 6)

    def test_category_mismatch_rejects_before_consume_or_execution(self):
        engine = self._engine(category="forensic")
        with self.assertRaisesRegex(
            Exception,
            "active local Crypto or Misc",
        ):
            self._run(engine)
        self.assertEqual(engine.events, [])

    def test_incomplete_capture_is_terminally_rejected(self):
        engine = self._engine(incomplete=True)
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "data_transcript_transport_incomplete",
        ):
            self._run(engine)
        self.assertEqual(engine.events.count("consume"), 1)
        self.assertIn("run", engine.events)
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        state.validate()
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])

    def test_reused_clean_proof_identity_is_rejected(self):
        engine = self._engine(reuse_identity=True)
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "data_transcript_proof_identity_reused",
        ):
            self._run(engine)
        self.assertEqual(engine.events.count("consume"), 1)
        self.assertEqual(engine.events.count("run"), 2)
        engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        ).validate()

    def test_image_drift_fails_before_the_next_replay(self):
        engine = self._engine(image_drift_after_first=True)
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "data_transcript_runtime_binding_changed",
        ):
            self._run(engine)
        self.assertEqual(engine.events.count("consume"), 1)
        self.assertEqual(engine.events.count("run"), 1)
        engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        ).validate()

    def test_revision_drift_terminalizes_all_six_child_runs(self):
        engine = self._engine(revision_drift_after_first=True)
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "data_transcript_runtime_binding_changed",
        ):
            self._run(engine)
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        state.validate()
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])
        child_runs = [
            item
            for item in state.runs
            if item.role == "data_transcript"
        ]
        self.assertEqual(len(child_runs), 6)
        self.assertTrue(
            all(item.status is RunStatus.FAILED for item in child_runs)
        )
        self.assertTrue(
            all(item.result_path for item in child_runs)
        )
        self.assertTrue(
            all(item.validation_path for item in child_runs)
        )
        self.assertNotIn(
            RunStatus.CREATED,
            {item.status for item in child_runs},
        )

    def test_recipe_mutation_after_consume_is_rejected_before_sandbox(self):
        engine = self._engine(mutate_recipe_on_probe=True)
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "workspace_recipe_changed",
        ):
            self._run(engine)
        self.assertEqual(engine.events.count("consume"), 1)
        self.assertEqual(engine.events.count("probe"), 1)
        self.assertEqual(engine.events.count("register"), 0)
        self.assertNotIn("sandbox", engine.events)
        self.assertNotIn("run", engine.events)
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])

    def test_recipe_pin_mismatch_rejects_before_consume(self):
        engine = self._engine()
        recipe_path = (
            engine.store.paths.artifacts
            / "workspace"
            / RECIPE_LOCATOR
        )
        recipe_path.write_bytes(recipe_path.read_bytes() + b" ")
        with self.assertRaisesRegex(
            DataTranscriptHotPathError,
            "workspace_recipe_changed",
        ):
            self._run(engine)
        self.assertEqual(engine.events, [])
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        self.assertEqual(
            state.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
                PREISSUE_ID
            ]["status"],
            "unused",
        )
        self.assertNotIn(DATA_TRANSCRIPT_STATE_KEY, state.extra)

    def test_mid_create_run_failure_cleans_every_unpublished_dir(self):
        engine = self._engine(create_run_fail_at=3)
        with self.assertRaisesRegex(
            OSError,
            "injected create_run failure",
        ):
            self._run(engine)
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        state.validate()
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])
        self.assertEqual(
            [
                item
                for item in state.runs
                if item.role == "data_transcript"
            ],
            [],
        )
        self.assertEqual(list(engine.store.paths.runs.iterdir()), [])

    def test_preissue_cas_failure_cleans_all_six_unpublished_dirs(self):
        engine = self._engine(fail_preissue_publish_once=True)
        with self.assertRaises(RevisionConflict):
            self._run(engine)
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        state.validate()
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])
        self.assertEqual(
            [
                item
                for item in state.runs
                if item.role == "data_transcript"
            ],
            [],
        )
        self.assertEqual(list(engine.store.paths.runs.iterdir()), [])

    def test_recovery_cleans_crash_left_reserved_run_directories(self):
        engine = self._engine()
        identity = ChallengeIdentity(
            "contest", "crypto", "interactive"
        )
        reservation = self._reservation()
        engine._consume_managed_oracle_preissue(
            identity,
            preissue_id=PREISSUE_ID,
            expected_kind=MANAGED_ORACLE_PREISSUE_CRYPTO_TRANSCRIPT,
            builder_run_id=BUILDER_RUN_ID,
            experiment_id=EXPERIMENT_ID,
            transcript_attempt_id=str(reservation["attempt_id"]),
            transcript_reservation=reservation,
        )
        first_run_id = reservation["replays"][0]["run_id"]
        engine.store.create_run(
            identity,
            first_run_id,
            request={"kind": "crash-left"},
            base_revision=engine.store.state.revision,
        )
        recovered = recover_data_transcript_attempts(
            engine,
            identity,
        )
        recovered.validate()
        journal = recovered.extra[DATA_TRANSCRIPT_STATE_KEY][
            reservation["attempt_id"]
        ]
        self.assertEqual(journal["status"], "failed")
        self.assertTrue(journal["terminal"])
        self.assertEqual(list(engine.store.paths.runs.iterdir()), [])

    def test_state_validator_rejects_consumed_preissue_without_journal(self):
        engine = self._engine()
        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        record = state.extra[
            MANAGED_ORACLE_PREISSUE_STATE_KEY
        ][PREISSUE_ID]
        record.update(
            {
                "consumed_at": utc_now(),
                "consumed_by_builder_run_id": BUILDER_RUN_ID,
                "consumed_by_experiment_id": EXPERIMENT_ID,
                "status": "consumed",
            }
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "lacks an attempt journal",
        ):
            state.validate()

    def test_state_validator_rejects_transcript_journal_rebinding(self):
        engine = self._engine()
        final_state, _evaluation_result = self._run(engine)
        attempt_id = next(
            iter(final_state.extra[DATA_TRANSCRIPT_STATE_KEY])
        )

        def unknown_key(state):
            state.extra[DATA_TRANSCRIPT_STATE_KEY][attempt_id][
                "raw_secret_like_field"
            ] = RAW_SECRET.decode("ascii")

        def evaluation_id_rebound(state):
            state.extra[DATA_TRANSCRIPT_STATE_KEY][attempt_id][
                "evaluation_artifact_id"
            ] = RECIPE_ARTIFACT_ID

        def evaluation_hash_rebound(state):
            state.extra[DATA_TRANSCRIPT_STATE_KEY][attempt_id][
                "evaluation_sha256"
            ] = "0" * 64

        def duplicate_proof_identity(state):
            journal = state.extra[DATA_TRANSCRIPT_STATE_KEY][
                attempt_id
            ]
            journal["proof_identities"][1] = copy.deepcopy(
                journal["proof_identities"][0]
            )

        def scope_rebound(state):
            state.extra[DATA_TRANSCRIPT_STATE_KEY][attempt_id][
                "proof_identities"
            ][0]["scope_fingerprint"] = "0" * 64

        def coordinated_scope_rebound(state):
            journal = state.extra[DATA_TRANSCRIPT_STATE_KEY][
                attempt_id
            ]
            journal["proof_identities"][0][
                "scope_fingerprint"
            ] = "0" * 64
            first_run_id = journal["replays"][0]["run_id"]
            run = next(
                item for item in state.runs if item.id == first_run_id
            )
            run.extra["data_transcript"]["proof_identity"][
                "scope_fingerprint"
            ] = "0" * 64

        for name, mutate in (
            ("unknown_key", unknown_key),
            ("evaluation_id", evaluation_id_rebound),
            ("evaluation_hash", evaluation_hash_rebound),
            ("duplicate_proof", duplicate_proof_identity),
            ("scope", scope_rebound),
            ("coordinated_scope", coordinated_scope_rebound),
        ):
            with self.subTest(mutation=name):
                hostile = copy.deepcopy(final_state)
                mutate(hostile)
                with self.assertRaises(ModelValidationError):
                    hostile.validate()

    def test_post_commit_cleanup_error_cannot_split_parent_and_journal(
        self,
    ):
        engine = self._engine()
        release = mock.Mock(
            side_effect=OSError("injected lease release failure")
        )
        engine.lease_broker.acquire = mock.Mock(
            return_value=SimpleNamespace(release=release)
        )
        with self.assertRaisesRegex(
            OSError,
            "injected lease release failure",
        ):
            self._run(engine)

        state = engine.store.load(
            ChallengeIdentity("contest", "crypto", "interactive")
        )
        state.validate()
        journal = next(
            iter(state.extra[DATA_TRANSCRIPT_STATE_KEY].values())
        )
        experiment = next(
            item
            for item in state.experiments
            if item.id == EXPERIMENT_ID
        )
        self.assertEqual(journal["status"], "passed")
        self.assertTrue(journal["terminal"])
        self.assertIs(
            experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertTrue(experiment.result["passed"])
        self.assertEqual(
            experiment.extra["completed_at"],
            journal["completed_at"],
        )

    def test_state_store_rejects_physical_sidecar_mutation(self):
        engine = self._engine()
        final_state, _evaluation_result = self._run(engine)
        identity = ChallengeIdentity(
            "contest", "crypto", "interactive"
        )
        with tempfile.TemporaryDirectory() as durable_root:
            durable_store = StateStore(Path(durable_root))
            durable_store.create_challenge(identity)
            durable_paths = durable_store.challenge_paths(identity)
            for artifact in final_state.artifacts:
                source = engine.store.paths.root / artifact.path
                destination = durable_paths.root / artifact.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            initial = durable_store.load(identity, recover=False)
            candidate = copy.deepcopy(final_state)
            candidate.revision = initial.revision
            durable_store.save(
                candidate,
                expected_revision=initial.revision,
            )
            durable_store.verify_artifacts(identity)

            journal = next(
                iter(
                    final_state.extra[
                        DATA_TRANSCRIPT_STATE_KEY
                    ].values()
                )
            )
            validation_binding = journal["replays"][0][
                "validation_artifact"
            ]
            validation_path = (
                durable_paths.root / validation_binding["path"]
            )
            validation_path.write_bytes(
                validation_path.read_bytes() + b" "
            )
            with self.assertRaises(ArtifactValidationError):
                durable_store.verify_artifacts(identity)

    def test_state_validator_rejects_cross_attempt_identity_reuse(self):
        engine = self._engine()
        final_state, _evaluation_result = self._run(engine)
        history = final_state.extra[DATA_TRANSCRIPT_STATE_KEY]
        original = next(iter(history.values()))
        duplicate = copy.deepcopy(original)
        duplicate_attempt_id = "data-transcript-duplicate-attempt"
        duplicate["attempt_id"] = duplicate_attempt_id
        history[duplicate_attempt_id] = duplicate

        with self.assertRaisesRegex(
            ModelValidationError,
            "reuses another attempt identity",
        ):
            final_state.validate()

    def test_challenge_engine_wrapper_forwards_the_exact_managed_scope(self):
        from ctf_os.engine.challenge import ChallengeEngine

        engine = object.__new__(ChallengeEngine)
        identity = ChallengeIdentity(
            "contest", "crypto", "interactive"
        )
        expected = (mock.sentinel.state, mock.sentinel.evaluation)
        with mock.patch(
            "ctf_os.engine.data_transcript_hotpath."
            "prove_data_transcript",
            return_value=expected,
        ) as delegated:
            observed = engine.prove_data_transcript(
                identity,
                recipe_locator=RECIPE_LOCATOR,
                recipe_artifact_id=RECIPE_ARTIFACT_ID,
                recipe_sha256="f" * 64,
                recipe_size_bytes=123,
                oracle_preissue_id=PREISSUE_ID,
                _session_owned=True,
                _managed_builder_run_id=BUILDER_RUN_ID,
                _managed_experiment_id=EXPERIMENT_ID,
            )

        self.assertIs(observed, expected)
        delegated.assert_called_once_with(
            engine,
            identity,
            recipe_locator=RECIPE_LOCATOR,
            recipe_artifact_id=RECIPE_ARTIFACT_ID,
            recipe_sha256="f" * 64,
            recipe_size_bytes=123,
            oracle_preissue_id=PREISSUE_ID,
            _session_owned=True,
            _managed_builder_run_id=BUILDER_RUN_ID,
            _managed_experiment_id=EXPERIMENT_ID,
        )


if __name__ == "__main__":
    unittest.main()
