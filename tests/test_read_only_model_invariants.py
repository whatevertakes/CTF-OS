from __future__ import annotations

import copy
import unittest

from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    FlagCandidate,
    ModelValidationError,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    new_challenge_state,
)
from ctf_os.schema import STATE_SCHEMA_VERSION


_WHEN = "2026-07-31T00:00:00Z"


def _stream_evidence(
    stream: str,
    artifact: ArtifactReference,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "stream": stream,
        "artifact_id": artifact.id,
        "path": artifact.path,
        "sha256": artifact.sha256,
        "drained_bytes": 0,
        "stored_bytes": 0,
        "limit_bytes": 1024,
        "capture_complete": True,
        "truncation_known": True,
        "truncated": False,
        "coverage": "complete_stream",
        "transport_summary_truncated": False,
        "stream_error_present": False,
        "capture_error_present": False,
        "sample_policy": "immutable_snapshot_head_tail",
        "head": {
            "byte_start": 0,
            "byte_end": 0,
            "encoding": "utf-8",
            "text": "",
            "text_truncated": False,
        },
        "tail": None,
        "omitted_stored_bytes": 0,
        "redaction_count": 0,
        "binary_sample_omitted": False,
    }


def _append_analysis_graph(state, ordinal: int) -> None:
    suffix = f"{ordinal:032x}"
    analysis_id = f"analysis-{suffix}"
    experiment_id = f"E-analysis-{ordinal}"
    run_id = f"R-analysis-{ordinal}"
    receipt_id = f"RCPT-analysis-{ordinal}"
    sandbox_run_id = f"run-{ordinal:08d}"
    locators = ["input.bin"]
    artifact_by_stream: dict[str, ArtifactReference] = {}
    for stream, leaf, extension in (
        ("stdout", "stdout.log", "log"),
        ("stderr", "stderr.log", "log"),
        ("result", "result.json", "json"),
    ):
        artifact_id = f"A-analysis-{ordinal}-{stream}"
        artifact = ArtifactReference(
            id=artifact_id,
            path=f"artifacts/snapshots/{artifact_id}.{extension}",
            sha256=f"{ordinal * 16 + len(artifact_by_stream):064x}",
            source_run_id=run_id,
            size=0,
            extra={
                "analysis_id": analysis_id,
                "isolated_read_only": True,
                "source_locator": f".ctf/runs/{sandbox_run_id}/{leaf}",
                "stream": stream,
            },
        )
        artifact_by_stream[stream] = artifact
        state.artifacts.append(artifact)
    state.experiments.append(
        Experiment(
            id=experiment_id,
            hypothesis_ids=[],
            command="true",
            expected_observation="bounded output",
            keep_if="operator evaluates it",
            drop_if="operator rejects it",
            timeout_seconds=30,
            kind=ExperimentKind.PROBE,
            status=ExperimentStatus.COMPLETED,
            result={
                "run_id": run_id,
                "receipt_id": receipt_id,
                "exit_code": 0,
                "timed_out": False,
                "analysis_id": analysis_id,
                "isolated_read_only": True,
            },
            artifact_ids=[
                artifact_by_stream["stdout"].id,
                artifact_by_stream["stderr"].id,
                artifact_by_stream["result"].id,
            ],
            extra={
                "analysis_id": analysis_id,
                "input_locators": locators,
                "isolated_read_only": True,
                "storage_reservation_bytes": 2048,
                "work_tree_limit_bytes": 1024,
            },
        )
    )
    state.runs.append(
        RunReference(
            id=run_id,
            base_revision=0,
            status=RunStatus.COMPLETED,
            request_path=f"runs/{run_id}/request.json",
            result_path=f"runs/{run_id}/result.json",
            validation_path=f"runs/{run_id}/validation.json",
            role="tool",
            origin=RunOrigin.OPERATOR_TOOL,
            configuration_epoch=0,
            extra={
                "analysis_id": analysis_id,
                "experiment_id": experiment_id,
                "input_locators": locators,
                "isolated_read_only": True,
                "sandbox_run_id": sandbox_run_id,
                "wall_seconds": 0.005,
            },
        )
    )
    state.receipts.append(
        ExecutionReceipt(
            id=receipt_id,
            experiment_id=experiment_id,
            run_id=run_id,
            outcome=ReceiptOutcome.SUCCEEDED,
            exit_code=0,
            wall_seconds=0.005,
            stdout_artifact_id=artifact_by_stream["stdout"].id,
            stderr_artifact_id=artifact_by_stream["stderr"].id,
            extra={
                "analysis_id": analysis_id,
                "input_locators": locators,
                "isolated_read_only": True,
                "line_count_basis": "transport_summary_tail",
                "result_artifact_id": artifact_by_stream["result"].id,
                "stream_evidence": {
                    "stdout": _stream_evidence(
                        "stdout", artifact_by_stream["stdout"]
                    ),
                    "stderr": _stream_evidence(
                        "stderr", artifact_by_stream["stderr"]
                    ),
                },
            },
        )
    )
    state.extra.setdefault("analysis_leases", []).append(
        {
            "schema_version": 1,
            "analysis_id": analysis_id,
            "scope_fingerprint": "a" * 64,
            "status": "completed",
            "owner_pid": 1,
            "owner_start_ticks": 1,
            "owner_boot_id": "00000000-0000-0000-0000-000000000000",
            "root_device": 0,
            "root_inode": ordinal,
            "work_device": 0,
            "work_inode": ordinal + 100,
            "base_revision": 0,
            "work_tree_limit_bytes": 1024,
            "storage_reservation_bytes": 0,
            "runtime_id": f"ctfos-analysis-{ordinal}",
            "created_at": _WHEN,
            "started_at": _WHEN,
            "finished_at": _WHEN,
            "observed_at": _WHEN,
            "reason_code": None,
        }
    )


def _two_analysis_state():
    state = new_challenge_state(
        ChallengeIdentity("Demo", "forensic", "read-only-model"),
        schema_version=STATE_SCHEMA_VERSION,
    )
    _append_analysis_graph(state, 1)
    _append_analysis_graph(state, 2)
    state.validate()
    return state


class ReadOnlyModelInvariantTests(unittest.TestCase):
    def test_exact_graph_rejects_cross_analysis_rebinding(self) -> None:
        baseline = _two_analysis_state()

        def set_experiment_result_run(state) -> None:
            state.experiments[0].result["run_id"] = state.runs[1].id

        def set_experiment_result_receipt(state) -> None:
            state.experiments[0].result["receipt_id"] = state.receipts[1].id

        def set_experiment_result_analysis(state) -> None:
            state.experiments[0].result["analysis_id"] = "analysis-" + "f" * 32

        def drop_result_artifact(state) -> None:
            state.experiments[0].artifact_ids.pop()

        def duplicate_stdout_artifact(state) -> None:
            state.experiments[0].artifact_ids[-1] = state.experiments[0].artifact_ids[0]

        def set_run_experiment(state) -> None:
            state.runs[0].extra["experiment_id"] = state.experiments[1].id

        def set_run_analysis(state) -> None:
            state.runs[0].extra["analysis_id"] = state.runs[1].extra["analysis_id"]

        def set_run_inputs(state) -> None:
            state.runs[0].extra["input_locators"] = ["other.bin"]

        def set_receipt_analysis(state) -> None:
            state.receipts[0].extra["analysis_id"] = state.receipts[1].extra["analysis_id"]

        def set_receipt_inputs(state) -> None:
            state.receipts[0].extra["input_locators"] = ["other.bin"]

        def set_receipt_result_artifact(state) -> None:
            state.receipts[0].extra["result_artifact_id"] = state.receipts[1].extra["result_artifact_id"]

        def set_artifact_analysis(state) -> None:
            state.artifacts[0].extra["analysis_id"] = state.artifacts[3].extra["analysis_id"]

        def duplicate_artifact_stream(state) -> None:
            state.artifacts[2].extra["stream"] = "stdout"

        def set_artifact_source_locator(state) -> None:
            state.artifacts[0].extra["source_locator"] = ".ctf/runs/run-99999999/stdout.log"

        def set_experiment_status(state) -> None:
            state.experiments[0].status = ExperimentStatus.FAILED

        def set_run_role(state) -> None:
            state.runs[0].role = "other"

        def set_run_request_path(state) -> None:
            state.runs[0].request_path = "runs/other/request.json"

        def set_artifact_path(state) -> None:
            state.artifacts[2].path = "artifacts/snapshots/other.json"

        def set_run_wall_seconds(state) -> None:
            state.runs[0].extra["wall_seconds"] = 100.0

        def forge_timeout_chain(state) -> None:
            state.experiments[0].result["timed_out"] = True
            state.runs[0].status = RunStatus.TIMED_OUT
            state.receipts[0].outcome = ReceiptOutcome.TIMED_OUT
            state.experiments[0].status = ExperimentStatus.FAILED

        mutations = (
            set_experiment_result_run,
            set_experiment_result_receipt,
            set_experiment_result_analysis,
            drop_result_artifact,
            duplicate_stdout_artifact,
            set_run_experiment,
            set_run_analysis,
            set_run_inputs,
            set_receipt_analysis,
            set_receipt_inputs,
            set_receipt_result_artifact,
            set_artifact_analysis,
            duplicate_artifact_stream,
            set_artifact_source_locator,
            set_experiment_status,
            set_run_role,
            set_run_request_path,
            set_artifact_path,
            set_run_wall_seconds,
            forge_timeout_chain,
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                state = copy.deepcopy(baseline)
                mutate(state)
                with self.assertRaises(ModelValidationError):
                    state.validate()

    def test_read_only_candidate_values_are_unique_across_runs(self) -> None:
        state = _two_analysis_state()
        state.candidates.extend(
            (
                FlagCandidate(
                    id="C-analysis-1",
                    value="KCTF{first}",
                    source_run_id=state.runs[0].id,
                ),
                FlagCandidate(
                    id="C-analysis-2",
                    value="KCTF{second}",
                    source_run_id=state.runs[1].id,
                ),
            )
        )
        state.validate()
        state.candidates[1].value = state.candidates[0].value
        with self.assertRaisesRegex(ModelValidationError, "value is not unique"):
            state.validate()


if __name__ == "__main__":
    unittest.main()
