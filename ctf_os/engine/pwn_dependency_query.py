"""Read-only public query boundary for the exact Pwn dependency graph."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from ctf_os.engine.pwn_dependency_state import (
    PWN_DEPENDENCY_STATE_JOURNAL_KEY,
    PwnDependencyStateError,
    project_pwn_dependency_context,
    validate_pwn_dependency_state_graph,
    verify_pwn_dependency_artifact_bytes,
    verify_pwn_dependency_static_target,
)
from ctf_os.engine.pwn_exploit_effect_hotpath import (
    _strict_ip_control_parent,
)
from ctf_os.engine.pwn_leak import (
    PwnLeakResult,
    PwnLeakStatus,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PwnRuntimeSnapshotReceiptMetadata,
)
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeState,
    ExperimentStatus,
)

if TYPE_CHECKING:
    from ctf_os.engine.challenge import ChallengeEngine


def _selected_graph(
    state: ChallengeState,
    graph_id: str | None,
) -> tuple[str, dict[str, object]]:
    root = state.extra.get(PWN_DEPENDENCY_STATE_JOURNAL_KEY)
    if type(root) is not dict or not root:
        raise PwnDependencyStateError("dependency_graph_not_found")
    selected_id = graph_id if graph_id is not None else sorted(root)[-1]
    wrapper = root.get(selected_id)
    if type(wrapper) is not dict or type(selected_id) is not str:
        raise PwnDependencyStateError("dependency_graph_not_found")
    graph = wrapper.get("graph")
    if type(graph) is not dict:
        raise PwnDependencyStateError("dependency_graph_wrapper_invalid")
    return selected_id, graph


def _recompute_leak_branch(
    engine: ChallengeEngine,
    state: ChallengeState,
    graph: dict[str, object],
) -> dict[str, object] | None:
    if graph.get("branch") != "LEAK_PROVEN":
        return None
    nodes = graph.get("nodes")
    address = (
        nodes.get("address_resolution")
        if type(nodes) is dict
        else None
    )
    leak_id = (
        address.get("experiment_id")
        if type(address) is dict
        else None
    )
    if type(leak_id) is not str:
        raise PwnDependencyStateError("dependency_leak_node_invalid")
    audit = copy.deepcopy(state)
    leak = next(
        (
            item
            for item in audit.experiments
            if item.id == leak_id
        ),
        None,
    )
    if leak is None:
        raise PwnDependencyStateError("dependency_leak_node_orphaned")
    envelope = (
        leak.result.get("pwn_leak_evidence")
        if type(leak.result) is dict
        else None
    )
    if type(envelope) is not dict:
        raise PwnDependencyStateError(
            "dependency_leak_result_invalid"
        )
    artifact_index = {item.id: item for item in audit.artifacts}
    run_index = {item.id: item for item in audit.runs}
    stdout_ids = leak.extra.get("stdout_artifact_ids")
    stderr_ids = leak.extra.get("stderr_artifact_ids")
    run_ids = leak.extra.get("run_ids")
    if (
        type(stdout_ids) is not list
        or type(stderr_ids) is not list
        or type(run_ids) is not list
    ):
        raise PwnDependencyStateError(
            "dependency_leak_replay_ids_invalid"
        )
    try:
        stdout_artifacts = tuple(
            artifact_index[item] for item in stdout_ids
        )
        stderr_artifacts = tuple(
            artifact_index[item] for item in stderr_ids
        )
        metadata = tuple(
            PwnRuntimeSnapshotReceiptMetadata.from_dict(
                run_index[run_id].extra["pwn_leak_replay"]["receipt"]
            )
            for run_id in run_ids
        )
        leak.status = ExperimentStatus.RUNNING
        _inputs, recomputed = engine._recompute_pwn_leak_result(
            audit,
            leak,
            stdout_artifacts=stdout_artifacts,
            stderr_artifacts=stderr_artifacts,
            receipt_metadata=metadata,
        )
        persisted = PwnLeakResult.from_dict(
            envelope["result"],
            expected_result=recomputed,
        )
    except (
        AttributeError,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        raise PwnDependencyStateError(
            "dependency_leak_physical_recomputation_failed"
        ) from error
    if persisted.status is not PwnLeakStatus.PROVEN:
        raise PwnDependencyStateError(
            "dependency_leak_physical_recomputation_failed"
        )
    return {
        "experiment_id": leak_id,
        "recomputed": True,
        "result_sha256": persisted.evidence_sha256,
    }


def validate_pwn_dependency_graph_query(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    graph_id: str | None = None,
) -> dict[str, object]:
    """Revalidate state, immutable source, and every artifact descriptor."""

    state = engine.store.load(identity, recover=False)
    state.validate()
    validate_pwn_dependency_state_graph(state)
    selected_id, graph = _selected_graph(state, graph_id)
    paths = engine.store.challenge_paths(identity)
    artifacts = verify_pwn_dependency_artifact_bytes(
        paths.root,
        state,
        graph_id=selected_id,
    )
    static_target = verify_pwn_dependency_static_target(
        engine.challenge_input(identity),
        state,
        graph_id=selected_id,
    )
    nodes = graph["nodes"]
    assert isinstance(nodes, dict)
    primitive = nodes["P"]
    assert isinstance(primitive, dict)
    primitive_id = primitive["experiment_id"]
    if type(primitive_id) is not str:
        raise PwnDependencyStateError(
            "dependency_primitive_node_invalid"
        )
    parent_result, _parent_inputs = _strict_ip_control_parent(
        engine,
        state,
        primitive_id,
    )
    if (
        parent_result.evidence_sha256
        != primitive["result_sha256"]
    ):
        raise PwnDependencyStateError(
            "dependency_primitive_physical_recomputation_failed"
        )
    leak = _recompute_leak_branch(engine, state, graph)
    context = project_pwn_dependency_context(
        state,
        graph_id=selected_id,
    )
    if context is None or context.get("status") != "COMPLETE":
        raise PwnDependencyStateError(
            "dependency_context_projection_incomplete"
        )
    return {
        "artifact_validation": artifacts,
        "branch": graph["branch"],
        "candidate_count": len(state.candidates),
        "context": context,
        "graph_id": selected_id,
        "graph_sha256": state.extra[
            PWN_DEPENDENCY_STATE_JOURNAL_KEY
        ][selected_id]["graph_sha256"],
        "leak_recomputation": leak,
        "ok": True,
        "primitive_recomputed": True,
        "raw_output_returned": False,
        "state_revision": state.revision,
        "static_target_validation": static_target,
        "submission_count": len(state.submissions),
    }


def query_pwn_dependency_graph(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    graph_id: str | None = None,
) -> dict[str, object]:
    """Return a raw-free capsule; complete graphs include physical validation."""

    state = engine.store.load(identity, recover=False)
    state.validate()
    context = project_pwn_dependency_context(
        state,
        graph_id=graph_id,
    )
    if context is None:
        raise PwnDependencyStateError(
            "dependency_graph_requires_pwn_state"
        )
    if context.get("status") != "COMPLETE":
        return {
            "context": context,
            "ok": False,
            "raw_output_returned": False,
            "validation": "incomplete",
        }
    return validate_pwn_dependency_graph_query(
        engine,
        identity,
        graph_id=graph_id,
    )


__all__ = [
    "query_pwn_dependency_graph",
    "validate_pwn_dependency_graph_query",
]
