from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_os.worker import (
    WorkerResultError,
    collect_worker_checkpoints,
    load_worker_result,
    merge_worker_checkpoints,
    merge_worker_result_files,
    merge_worker_results,
    save_worker_result,
    save_worker_checkpoint,
    validate_worker_result,
)


def _worker(tmp_path: Path, name: str = "worker-001") -> Path:
    root = tmp_path / "workers" / name
    (root / "evidence").mkdir(parents=True)
    (root / "work").mkdir()
    (root / "evidence" / "trace.txt").write_text("confirmed\n")
    (root / "work" / "poc.py").write_text("print('ok')\n")
    return root


def _result(session_id: str = "worker-001", *, status: str = "SUPPORTED", claim_status: str = "SUPPORTED", confidence: str = "HIGH") -> dict[str, object]:
    return {
        "schema_version": 1,
        "session_id": session_id,
        "parent_session_id": "sol-main",
        "challenge_id": "web/jelly-box",
        "input_fingerprint": "fingerprint-v1",
        "role": "source-audit",
        "status": status,
        "summary": "Investigated the bridge guard",
        "hypotheses": [{
            "claim": "Nested call chain bypasses the bridge guard",
            "status": claim_status,
            "confidence": confidence,
            "evidence": ["evidence/trace.txt"],
            "commands": ["python3 work/poc.py"],
            "kill_condition": None,
            "reopen_condition": None,
        }],
        "artifacts": ["work/poc.py"],
        "flag_candidates": [],
        "recommended_next_step": "Integrate the request chain",
        "service_mutations": [],
        "policy_violations": [],
        "started_at": "2026-07-13T00:00:00Z",
        "finished_at": "2026-07-13T00:05:00Z",
    }


@pytest.mark.parametrize("status", ["SUPPORTED", "REFUTED"])
def test_worker_result_is_validated_saved_and_loaded(tmp_path: Path, status: str) -> None:
    root = _worker(tmp_path)
    payload = _result(status=status, claim_status=status)

    saved = save_worker_result(root, payload)
    loaded = load_worker_result(root / "result.json")

    assert saved == loaded
    assert loaded["status"] == status
    assert json.loads((root / "result.json").read_text())["session_id"] == "worker-001"


def test_worker_result_rejects_malformed_schema_and_timestamps(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    missing = _result()
    del missing["hypotheses"]
    with pytest.raises(WorkerResultError, match="missing required fields: hypotheses"):
        validate_worker_result(root, missing)

    reversed_time = _result()
    reversed_time["finished_at"] = "2026-07-12T23:59:00Z"
    with pytest.raises(WorkerResultError, match="earlier"):
        validate_worker_result(root, reversed_time)

    bad_status = _result()
    bad_status["status"] = "PROMISING"
    with pytest.raises(WorkerResultError, match="must be one of"):
        validate_worker_result(root, bad_status)


def test_evidence_and_artifact_paths_require_internal_regular_files(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")

    traversal = _result()
    traversal["artifacts"] = ["../../secret.txt"]
    with pytest.raises(WorkerResultError, match="safe relative path"):
        validate_worker_result(root, traversal)

    missing = _result()
    missing["hypotheses"][0]["evidence"] = ["evidence/missing.txt"]  # type: ignore[index]
    with pytest.raises(WorkerResultError, match="missing"):
        validate_worker_result(root, missing)

    (root / "evidence" / "linked.txt").symlink_to(outside)
    linked = _result()
    linked["hypotheses"][0]["evidence"] = ["evidence/linked.txt"]  # type: ignore[index]
    with pytest.raises(WorkerResultError, match="symlink"):
        validate_worker_result(root, linked)

    directory = _result()
    directory["artifacts"] = ["work"]
    with pytest.raises(WorkerResultError, match="regular file"):
        validate_worker_result(root, directory)


def test_reported_service_mutation_is_saved_and_marked_as_policy_violation(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    payload = _result()
    payload["service_mutations"] = [{"action": "restart", "target": "challenge-service"}]

    saved = save_worker_result(root, payload)

    assert saved["service_mutations"] == payload["service_mutations"]
    assert saved["policy_violations"] == [{
        "code": "SERVICE_MUTATION_REPORTED",
        "message": "A child worker reported a shared service lifecycle mutation.",
        "mutations": payload["service_mutations"],
    }]
    assert (root / "result.json").is_file()


def test_merge_prioritizes_results_and_preserves_conflicting_duplicate_claims(tmp_path: Path) -> None:
    supported_root = _worker(tmp_path, "worker-supported")
    supported = save_worker_result(supported_root, _result("worker-supported"))

    refuted_root = _worker(tmp_path, "worker-refuted")
    refuted_payload = _result("worker-refuted", status="REFUTED", claim_status="REFUTED", confidence="MEDIUM")
    # Claim normalization deliberately differs in case and whitespace.
    refuted_payload["hypotheses"][0]["claim"] = " nested CALL chain   bypasses the bridge guard "  # type: ignore[index]
    refuted = save_worker_result(refuted_root, refuted_payload)

    partial_root = _worker(tmp_path, "worker-partial")
    partial = save_worker_result(partial_root, _result("worker-partial", status="PARTIAL", claim_status="PARTIAL", confidence="LOW"))

    flag_root = _worker(tmp_path, "worker-flag")
    flag_payload = _result("worker-flag", status="FLAG_CANDIDATE", claim_status="INCONCLUSIVE", confidence="LOW")
    flag_payload["flag_candidates"] = ["DH{candidate}"]
    flag = save_worker_result(flag_root, flag_payload)

    merged = merge_worker_results([partial, refuted, flag, supported])

    assert [item["session_id"] for item in merged["results"]] == [
        "worker-flag", "worker-supported", "worker-refuted", "worker-partial",
    ]
    assert len(merged["hypotheses"]) == 1
    hypothesis = merged["hypotheses"][0]
    assert hypothesis["conflict"] is True
    assert hypothesis["statuses"] == ["SUPPORTED", "REFUTED", "PARTIAL", "INCONCLUSIVE"]
    assert {item["session_id"] for item in hypothesis["observations"]} == {
        "worker-supported", "worker-refuted", "worker-partial", "worker-flag",
    }
    assert merged["flag_candidates"] == [{"session_id": "worker-flag", "candidate": "DH{candidate}"}]


def test_load_revalidates_evidence_retention(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    save_worker_result(root, _result())
    (root / "evidence" / "trace.txt").unlink()

    with pytest.raises(WorkerResultError, match="missing"):
        load_worker_result(root / "result.json")


def test_merge_result_files_revalidates_before_synthesis(tmp_path: Path) -> None:
    first = _worker(tmp_path, "worker-001")
    second = _worker(tmp_path, "worker-002")
    save_worker_result(first, _result("worker-001"))
    save_worker_result(second, _result("worker-002", status="PARTIAL", claim_status="PARTIAL"))

    merged = merge_worker_result_files([second / "result.json", first / "result.json"])

    assert [row["session_id"] for row in merged["results"]] == ["worker-001", "worker-002"]


def test_merge_excludes_results_from_a_stale_input_fingerprint(tmp_path: Path) -> None:
    current_root = _worker(tmp_path, "worker-current")
    current = _result("worker-current")
    save_worker_result(current_root, current)
    stale_root = _worker(tmp_path, "worker-stale")
    stale = _result("worker-stale", status="FLAG_CANDIDATE")
    stale["input_fingerprint"] = "old-fingerprint"
    stale["flag_candidates"] = ["DH{stale}"]
    save_worker_result(stale_root, stale)

    merged = merge_worker_result_files(
        [stale_root / "result.json", current_root / "result.json"],
        input_fingerprint="fingerprint-v1",
    )

    assert [item["session_id"] for item in merged["results"]] == ["worker-current"]
    assert merged["flag_candidates"] == []


def test_checkpoint_save_sequence_merge_and_idempotency(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    kwargs = dict(parent_session_id="sol-main", challenge_id="abc", input_fingerprint="fingerprint-v1", checkpoint_type="SUPPORTED_FACT", summary="A compact supported fact", evidence=["evidence/trace.txt"], artifacts=["work/poc.py"], useful_for=["dynamic"], recommended_action="Probe a byte", confidence=.9)
    first = save_worker_checkpoint(root, **kwargs)
    second = save_worker_checkpoint(root, **kwargs)
    assert (first["sequence"], second["sequence"]) == (1, 2)
    merged1 = merge_worker_checkpoints(root.parent, input_fingerprint="fingerprint-v1")
    merged2 = merge_worker_checkpoints(root.parent, input_fingerprint="fingerprint-v1")
    assert merged1 == merged2
    assert len(merged1["checkpoints"]) == 2


def test_checkpoint_merge_preserves_conflicting_worker_observations(tmp_path: Path) -> None:
    supported = _worker(tmp_path, "supported")
    rejected = _worker(tmp_path, "rejected")
    common = dict(parent_session_id="sol-main", challenge_id="abc", input_fingerprint="fingerprint-v1", evidence=[], artifacts=[], useful_for=[], recommended_action="Sol judges the conflict", confidence=.8)
    save_worker_checkpoint(supported, checkpoint_type="SUPPORTED_FACT", summary="The guard is bypassable", **common)
    save_worker_checkpoint(rejected, checkpoint_type="REJECTED_HYPOTHESIS", summary="The guard is not bypassable", **common)
    merged = merge_worker_checkpoints(supported.parent, input_fingerprint="fingerprint-v1")
    assert {(item["session_id"], item["type"]) for item in merged["checkpoints"]} == {("supported", "SUPPORTED_FACT"), ("rejected", "REJECTED_HYPOTHESIS")}


def test_checkpoint_rejects_traversal_absolute_symlink_and_bad_fingerprint_filter(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    base = dict(parent_session_id="sol-main", challenge_id="abc", input_fingerprint="fingerprint-v1", checkpoint_type="SUPPORTED_FACT", summary="fact", evidence=[], artifacts=[], useful_for=[], recommended_action="", confidence=.5)
    for unsafe in ("../../secret", "/etc/passwd"):
        with pytest.raises(WorkerResultError):
            save_worker_checkpoint(root, **{**base, "evidence": [unsafe]})
    outside = tmp_path / "outside"; outside.write_text("x")
    (root / "evidence" / "link").symlink_to(outside)
    with pytest.raises(WorkerResultError, match="symlink"):
        save_worker_checkpoint(root, **{**base, "evidence": ["evidence/link"]})
    save_worker_checkpoint(root, **base)
    assert collect_worker_checkpoints(root.parent, input_fingerprint="other") == []
    (tmp_path / "STATE.json").write_text(json.dumps({"input_fingerprint": "current"}))
    with pytest.raises(WorkerResultError, match="fingerprint"):
        save_worker_checkpoint(root, **base)


def test_checkpoint_directory_symlink_is_rejected(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    outside = tmp_path / "outside-checkpoints"; outside.mkdir()
    (root / "checkpoints").symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkerResultError, match="symlink"):
        save_worker_checkpoint(root, parent_session_id="sol-main", challenge_id="abc", input_fingerprint="fingerprint-v1", checkpoint_type="BLOCKER", summary="blocked", evidence=[], artifacts=[], useful_for=[], recommended_action="", confidence=.5)


def test_worker_result_clean_room_extension_is_backward_compatible(tmp_path: Path) -> None:
    root = _worker(tmp_path)
    old = validate_worker_result(root, _result())
    assert old["independent_verification"] is False and old["verifier_role"] is None
    payload = _result(); payload["independent_verification"] = True; payload["verifier_role"] = "clean-room-verifier"
    new = validate_worker_result(root, payload)
    assert new["independent_verification"] is True
