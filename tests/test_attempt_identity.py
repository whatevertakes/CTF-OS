from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf_os.workspace import (
    WorkspaceError, bind_input_fingerprint, list_attempts, resolve_active_run,
    resolve_exact_run, show_attempt, start_fresh_attempt,
)


def _challenge():
    return SimpleNamespace(
        id="same", key="misc/same", category="misc", name="same", remotes=(),
        description="same", hint=None, flag_format="CTF{...}",
        flag_pattern=r"\ACTF\{[^}]+\}\Z", input_profile="standard",
    )


def _workspace(tmp_path: Path) -> tuple[Path, SimpleNamespace]:
    root = tmp_path / "challenge"
    (root / "input").mkdir(parents=True)
    (root / "input" / "task.txt").write_text("immutable input\n", encoding="utf-8")
    return root, _challenge()


def test_same_challenge_same_seed_three_attempts_create_three_disjoint_run_roots(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    runs = [
        start_fresh_attempt(root, challenge, "fp", transformation_seed="seed")
        for _ in range(3)
    ]
    assert len({run.name for run in runs}) == 3
    assert all(run.parent == root / "runs" for run in runs)


def test_challenge_instance_identity_is_stable_across_attempts(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    states = [
        json.loads(start_fresh_attempt(root, challenge, "fp", transformation_seed=7).joinpath("STATE.json").read_text())
        for _ in range(3)
    ]
    assert len({state["challenge_instance_id"] for state in states}) == 1
    assert len({state["attempt_id"] for state in states}) == 3


def test_no_artifact_or_ledger_reuse_across_attempts(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    first = start_fresh_attempt(root, challenge, "fp")
    (first / "exploit").mkdir(); (first / "exploit" / "solve.py").write_text("owned")
    (first / "milestone-receipts.jsonl").write_text('{"old":true}\n')
    second = start_fresh_attempt(root, challenge, "fp")
    assert not (second / "exploit").exists()
    assert (second / "milestone-receipts.jsonl").read_text() == ""


def test_benchmark_never_resolves_attempt_via_active_run_pointer(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    current = bind_input_fingerprint(root, challenge, "fp")
    benchmark = start_fresh_attempt(
        root, challenge, "fp", attempt_id="bench-a-1", publish_active=False,
    )
    assert resolve_active_run(root) == current
    assert resolve_exact_run(root, benchmark.name) == benchmark


def test_sealed_prior_attempt_remains_queryable(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    run = start_fresh_attempt(root, challenge, "fp")
    state = json.loads((run / "STATE.json").read_text()); state.update({"sealed": True, "status": "SEALED"})
    (run / "STATE.json").write_text(json.dumps(state))
    assert show_attempt(root, run_id=run.name)["sealed"] is True


def test_pending_submission_prior_attempt_remains_visible(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    run = start_fresh_attempt(root, challenge, "fp")
    state = json.loads((run / "STATE.json").read_text()); state["remote_flag_receipt"] = "flag-receipts/x.json"
    (run / "STATE.json").write_text(json.dumps(state))
    assert list_attempts(root)[0]["pending_submission"] is True


def test_duplicate_attempt_id_is_rejected(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    start_fresh_attempt(root, challenge, "fp", attempt_id="caller-safe")
    with pytest.raises(WorkspaceError, match="duplicate attempt_id"):
        start_fresh_attempt(root, challenge, "fp", attempt_id="caller-safe")


def test_exact_run_resolution_does_not_fall_back_to_active_pointer(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    bind_input_fingerprint(root, challenge, "fp")
    with pytest.raises(WorkspaceError, match="does not exist"):
        resolve_exact_run(root, "run-does-not-exist")


def test_legacy_content_run_migrates_without_receipt_loss(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": challenge.id, "status": "SEALED",
        "sealed": True, "input_fingerprint": "fp", "target_revision": 1,
    }))
    (root / "milestone-receipts.jsonl").write_text('{"receipt_id":"keep"}\n')
    run = resolve_active_run(root)
    assert "keep" in (run / "milestone-receipts.jsonl").read_text()
    assert show_attempt(root, run_id=run.name)["legacy_identity"] is True


def test_fresh_attempt_does_not_copy_model_or_sandbox_identity(tmp_path: Path) -> None:
    root, challenge = _workspace(tmp_path)
    first = start_fresh_attempt(root, challenge, "fp")
    (first / "workers" / "old").mkdir(parents=True)
    (first / "workers" / "old" / "sandbox.json").write_text('{"container":"old"}')
    (first / "model-context.json").write_text('{"session":"old"}')
    second = start_fresh_attempt(root, challenge, "fp")
    assert not (second / "workers").exists()
    assert not (second / "model-context.json").exists()
