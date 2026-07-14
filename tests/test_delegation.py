from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from ctf_os.delegation import (
    BranchCandidate, DelegationError, add_branch, admit_branch, branch_utility,
    init_plan, load_plan, load_templates, record_admission, template_recommendation,
    update_branch,
)


def candidate(name: str = "static", *, family: str = "validation-reconstruction", hypothesis: str = "Reconstruct the target validation expression", scope=("target",), tools=("objdump",), artifacts=("work/validator.py",), role="deep-static-analysis") -> BranchCandidate:
    return BranchCandidate.create(session_id=name, role=role, hypothesis_family=family, hypothesis=hypothesis, scope=scope, tool_strategy=tools, expected_artifacts=artifacts)


def make_plan(root: Path) -> dict:
    root.mkdir(exist_ok=True)
    return init_plan(root, challenge_id="abc123", input_fingerprint="fp-1", parent_session_id="sol-main", tier=2, tier_reason="Independent static and dynamic work")


def add(root: Path, item: BranchCandidate) -> dict:
    record_admission(root, input_fingerprint="fp-1", candidate=item)
    return add_branch(root, input_fingerprint="fp-1", candidate=item, evidence_contract=["confirmed fact"], success_condition="validator works", kill_condition="no facts after 12 experiments", maximum_steps=20, budget_seconds=1200, requested_model_role="sol", requested_reasoning="xhigh")


def test_plan_create_models_are_separated_and_updates_are_atomic(tmp_path: Path) -> None:
    root = tmp_path / "solve"
    plan = make_plan(root)
    branch = add(root, candidate())
    assert plan["schema_version"] == 1
    assert branch["requested_model_role"] == "sol"
    assert branch["observed_runtime_model"] is None
    assert branch["observed_reasoning"] is None
    assert branch["runtime_observation_evidence"] is None
    assert branch["pinning_verified"] is False
    update_branch(root, input_fingerprint="fp-1", session_id="static", status="RUNNING")
    assert load_plan(root)["branches"][0]["status"] == "RUNNING"
    assert not list(root.glob(".DELEGATION_PLAN.json.*"))
    with pytest.raises(DelegationError, match="evidence"):
        update_branch(root, input_fingerprint="fp-1", session_id="static", status="RUNNING", observed_runtime_model="unknown-model")


def test_plan_rejects_invalid_tier_status_duplicate_and_stale_fingerprint(tmp_path: Path) -> None:
    root = tmp_path / "solve"; root.mkdir()
    with pytest.raises(DelegationError, match="tier"):
        init_plan(root, challenge_id="x", input_fingerprint="fp", parent_session_id="sol-main", tier=5, tier_reason="bad")
    make_plan(root); add(root, candidate())
    with pytest.raises(DelegationError, match="duplicate"):
        add(root, candidate())
    with pytest.raises(DelegationError, match="status"):
        update_branch(root, input_fingerprint="fp-1", session_id="static", status="PROMISING")
    with pytest.raises(DelegationError, match="stale"):
        load_plan(root, input_fingerprint="fp-2")
    assert json.loads((root / "DELEGATION_PLAN.json").read_text())["branches"][0]["status"] == "STALE"


def test_admission_rejects_semantic_duplicate_and_is_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "solve"; make_plan(root); add(root, candidate())
    duplicate = candidate("renamed", hypothesis="  reconstruct TARGET validation-expression! ")
    first = admit_branch(load_plan(root), duplicate)
    second = admit_branch(load_plan(root), duplicate)
    assert first == second
    assert first["admitted"] is False
    assert first["maximum_overlap_score"] >= .70


def test_admission_allows_distinct_family_exception_and_threshold(tmp_path: Path) -> None:
    root = tmp_path / "solve"; make_plan(root); add(root, candidate())
    dynamic = candidate("dynamic", family="state-differential", hypothesis="Input bytes affect independent state lanes", scope=("target", "gdb"), tools=("gdb", "python"), artifacts=("work/oracle.py",), role="dynamic-oracle")
    assert admit_branch(load_plan(root), dynamic)["admitted"] is True
    duplicate = candidate("verify")
    assert admit_branch(load_plan(root), duplicate, purpose="independent-verification")["admitted"] is True
    assert "exception" in admit_branch(load_plan(root), duplicate, purpose="independent-verification")["reason"].casefold()
    assert admit_branch(load_plan(root), dynamic, threshold=.01)["admitted"] is False


def test_admission_rejects_empty_and_excessive_input() -> None:
    with pytest.raises(DelegationError):
        BranchCandidate.create(session_id="x", role="r", hypothesis_family="f", hypothesis="", scope=["x"], tool_strategy=["x"], expected_artifacts=["work/x"])
    with pytest.raises(DelegationError):
        BranchCandidate.create(session_id="x", role="r", hypothesis_family="f", hypothesis="x", scope=[str(i) for i in range(33)], tool_strategy=["x"], expected_artifacts=["work/x"])


def test_utility_is_advisory_and_responds_to_evidence_penalties_and_flags(tmp_path: Path) -> None:
    root = tmp_path / "solve"; make_plan(root); add(root, candidate())
    plan = load_plan(root)
    insufficient = branch_utility(plan, session_id="static", checkpoints=[], result=None)
    positive = branch_utility(plan, session_id="static", checkpoints=[{"session_id": "static", "type": "SUPPORTED_FACT", "artifacts": []}], result=None)
    negative = branch_utility(plan, session_id="static", checkpoints=[{"session_id": "static", "type": "BLOCKER"}, {"session_id": "static", "type": "BLOCKER"}], result={"artifacts": [], "flag_candidates": [], "hypotheses": [], "policy_violations": [{"code": "x"}], "status": "ERROR"})
    flag = branch_utility(plan, session_id="static", checkpoints=[{"session_id": "static", "type": "FLAG_CANDIDATE"}], result=None)
    assert insufficient["classification"] == "INSUFFICIENT_DATA"
    assert positive["utility_score"] > negative["utility_score"]
    assert negative["classification"] == "TERMINATE_CANDIDATE"
    assert flag["classification"] == "COMPLETE"
    assert load_plan(root)["branches"][0]["status"] == "ADMITTED"


def test_utility_elapsed_budget_and_recent_timestamp_plateau_reduce_score(tmp_path: Path) -> None:
    root = tmp_path / "solve"; make_plan(root); add(root, candidate())
    plan = load_plan(root)
    plan["branches"][0]["started_at"] = "2026-07-14T00:00:00Z"
    early = [{"session_id": "static", "type": "SUPPORTED_FACT", "created_at": "2026-07-14T00:01:00Z"}]
    plateau = early + [{"session_id": "static", "type": "BLOCKER", "created_at": "2026-07-14T00:19:00Z"}]
    within = branch_utility(plan, session_id="static", checkpoints=early, result=None, now=datetime(2026, 7, 14, 0, 5, tzinfo=timezone.utc))
    exhausted = branch_utility(plan, session_id="static", checkpoints=plateau, result=None, now=datetime(2026, 7, 14, 1, 0, tzinfo=timezone.utc))
    assert exhausted["utility_score"] < within["utility_score"]
    assert exhausted["metrics"]["new_information_rate"] == 0.0


def test_templates_cover_categories_fallback_and_never_create_branches(tmp_path: Path) -> None:
    resource = Path("ctf_os/resources/delegation-templates.yaml")
    templates = load_templates(resource)
    assert {"pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "cloud", "ai"}.issubset(templates)
    assert all({f"tier_{i}" for i in range(1, 5)}.issubset(value) for value in templates.values())
    recommendation = template_recommendation(resource, category="mobile", tier=2)
    assert recommendation["template_category"] == "misc"
    assert recommendation["original_category"] == "mobile"
    assert recommendation["branches_created"] is False
    malformed = tmp_path / "bad.yaml"; malformed.write_text("rev: [")
    with pytest.raises(DelegationError, match="malformed"):
        load_templates(malformed)
