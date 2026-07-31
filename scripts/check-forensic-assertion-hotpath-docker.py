#!/usr/bin/env python3
"""Release proof for the public Forensic assertion hot path in real Docker.

The proof builds the production evidence index, probes Python/pread and
Perl/sysread implementations in the digest-pinned image, and executes three
independently
issued confirmed assertion waves plus one deliberately nonmatching control.
Every evidence-producing command uses the production challenge sandbox with
network disabled.  Raw selected bytes remain in private artifacts only.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import ModuleType

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import load_config
from ctf_os.director.resources import ResourceVector
from ctf_os.engine import forensic_assertion_hotpath as assertion_hotpath
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.forensic_assertion_execution import (
    FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
    ForensicToolReadiness,
    forensic_tool_readiness_registry_sha256,
)
from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    ForensicAssertionNode,
    ForensicAssertionState,
    ForensicFileRangePointer,
    build_forensic_assertion_graph_plan,
    forensic_evidence_pointer_sha256,
)
from ctf_os.engine.forensic_assertion_state import (
    validate_forensic_assertion_state_graph,
)
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    SessionStatus,
)
from ctf_os.sandbox import CommandSpec, NetworkPolicy
from ctf_os.sandbox.files import (
    ensure_private_directory,
    read_bounded_regular,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store import MAX_CANONICAL_STATE_BYTES
from ctf_os.store.atomic import (
    atomic_write_bytes,
    canonical_json_bytes,
    strict_json_loads,
)


FIXTURE_SOURCE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "forensic_assertion_tool.py"
)
PERL_FIXTURE_SOURCE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "forensic_assertion_perl_tool.pl"
)
RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338"
)
FIXTURE_DESTINATION = "forensic_assertion_tool.py"
PERL_FIXTURE_DESTINATION = "forensic_assertion_perl_tool.pl"
TOOL_PROTOCOL = "ctfos.release.forensic.assertion.tool.v1"
POSITIVE_REPETITIONS = 3
EVIDENCE_PREFIX = b"release-forensic-prefix|"
EVIDENCE_SUFFIX = b"|release-forensic-suffix"
READINESS_MAX_BYTES = 64 * 1024
PYTHON_EXECUTABLE_SHA256 = (
    "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
)
PERL_EXECUTABLE_SHA256 = (
    "56e5ea41974eb1eff0f7ea64677578b1938053d29818c2810bcb21e2ca68cafa"
)


def _load_fixture() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "ctfos_forensic_assertion_release_fixture",
        FIXTURE_SOURCE,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load Forensic assertion fixture")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


fixture = _load_fixture()


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    readiness: ForensicToolReadiness
    artifact: ArtifactReference
    algorithm: str
    corrupt_binding: bool


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require three confirmed plus one nonmatching-control Forensic "
            "assertion waves through the exact release image."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help=(
            "must be the exact release image digest "
            f"{RELEASE_IMAGE_DIGEST}"
        ),
    )
    return parser.parse_args()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _docker(
    argv: tuple[str, ...],
    *,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ("docker", *argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "docker command failed: " + result.stderr.strip()[:4096]
        )
    return result


def _challenge_containers(identity: ChallengeIdentity) -> tuple[str, ...]:
    result = _docker(
        (
            "ps",
            "-aq",
            "--filter",
            "label=ctfos.managed=true",
            "--filter",
            (
                "label=ctfos.challenge="
                f"{identity.contest_id}/{identity.category}/"
                f"{identity.challenge_id}"
            ),
        )
    )
    values = tuple(
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    )
    if any(
        len(value) < 12
        or any(character not in "0123456789abcdef" for character in value)
        for value in values
    ):
        raise RuntimeError("Docker returned an invalid container identifier")
    return values


def _remove_exact_containers(values: tuple[str, ...]) -> None:
    if values:
        _docker(("rm", "-f", *values), timeout=60)


def _engine(root: Path, image_digest: str) -> ChallengeEngine:
    configured = load_config(root)
    configured = replace(
        configured,
        resources=replace(
            configured.resources,
            remote_command_min_interval_s=0.0,
        ),
        runtime=replace(
            configured.runtime,
            image="ctf-os:core",
            image_digest=image_digest,
            network_default="none",
            command_timeout_s=120,
        ),
    )
    engine = ChallengeEngine(
        root,
        config=configured,
        capability_probe=inspect_pinned_capabilities,
    )
    engine._sandbox_factory = None
    return engine


def _copy_challenge_inputs(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    secret: bytes,
) -> None:
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "evidence.bin").write_bytes(
        EVIDENCE_PREFIX + secret + EVIDENCE_SUFFIX
    )
    fixture_destination = incoming / FIXTURE_DESTINATION
    shutil.copyfile(FIXTURE_SOURCE, fixture_destination)
    fixture_destination.chmod(0o500)
    perl_destination = incoming / PERL_FIXTURE_DESTINATION
    shutil.copyfile(PERL_FIXTURE_SOURCE, perl_destination)
    perl_destination.chmod(0o400)


def _execute_index(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
):
    initial = engine.add_challenge(
        identity,
        prompt="confirm one exact file-range assertion",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    legacy_ids = {
        item.id
        for item in initial.experiments
        if item.extra.get("adapter_seed") is True
    }
    orchestrator = ManagedOrchestrator(
        engine,
        capability_probe=inspect_pinned_capabilities,
    )
    _reserved, session_id = orchestrator._reserve_session(
        identity,
        "S-forensic-assertion-release",
    )
    synchronized = engine.synchronize_managed_adapter_seed_plan(
        identity,
        session_id,
    )
    seed = next(
        item
        for item in synchronized.experiments
        if (
            item.id not in legacy_ids
            and item.extra.get("adapter_spec_template_id")
            == "file_inventory"
        )
    )
    _reserved, cycle = orchestrator._reserve_cycle(
        identity,
        session_id,
    )
    orchestrator._mark_action_selection(
        identity,
        session_id,
        cycle.id,
        (seed.id,),
    )
    state = engine.execute_registered_experiments(
        identity,
        experiment_ids=(seed.id,),
    )
    executed = next(
        item for item in state.experiments if item.id == seed.id
    )
    if (
        executed.status is not ExperimentStatus.COMPLETED
        or type(executed.result) is not dict
        or state.status is not ChallengeStatus.TRIAGING
    ):
        raise AssertionError("production Forensic index did not complete")
    raw_evaluation = executed.result.get("forensic_index_execution")
    if (
        type(raw_evaluation) is not dict
        or raw_evaluation.get("confirmed") is not True
        or raw_evaluation.get("reason_code")
        != "complete_executed_evidence_index"
    ):
        raise AssertionError("production Forensic index was not confirmed")
    envelope = raw_evaluation.get("envelope")
    if (
        type(envelope) is not dict
        or envelope.get("transport", {}).get("network") != "none"
        or envelope.get("image", {}).get("digest")
        != engine.config.runtime.image_digest
    ):
        raise AssertionError("Forensic index escaped the pinned deny-all run")
    state = orchestrator._finish_session(
        identity,
        session_id,
        status=SessionStatus.COMPLETED,
        reason="release Forensic index confirmed",
    )
    return state, assertion_hotpath._typed_index_execution(raw_evaluation)


def _tool_version(
    *,
    algorithm: str,
    corrupt_binding: bool,
) -> str:
    if algorithm == "descriptor":
        observed = fixture.tool_version_sha256(
            FIXTURE_SOURCE.read_bytes(),
            algorithm=algorithm,
            corrupt_binding=corrupt_binding,
        )
        if observed != PYTHON_EXECUTABLE_SHA256:
            raise AssertionError("host Python executable hash is unexpected")
        return PYTHON_EXECUTABLE_SHA256
    if algorithm == "perl-sysread":
        return PERL_EXECUTABLE_SHA256
    raise AssertionError("unknown Forensic release implementation")


def _command_template(
    *,
    algorithm: str,
    image_digest: str,
    tool_version: str,
    corrupt_binding: bool,
) -> tuple[str, ...]:
    if algorithm == "descriptor":
        values = [
            "/usr/bin/python3",
            f"/challenge/{FIXTURE_DESTINATION}",
            "--algorithm",
            algorithm,
        ]
    elif algorithm == "perl-sysread":
        values = [
            "/usr/bin/perl",
            f"/challenge/{PERL_FIXTURE_DESTINATION}",
        ]
    else:
        raise AssertionError("unknown Forensic release implementation")
    values.extend(
        (
            "--expected-image-digest",
            image_digest,
            "--expected-tool-version",
            tool_version,
        )
    )
    if corrupt_binding:
        values.append("--corrupt-binding")
    values.extend(
        (
            "--request",
            "{request_path}",
            "--observation",
            "{observation_path}",
            "--artifact",
            "{artifact_path}",
        )
    )
    return tuple(values)


def _probe_tool(
    engine: ChallengeEngine,
    state,
    *,
    tool_id: str,
    family: str,
    algorithm: str,
    corrupt_binding: bool,
    artifact_id: str,
) -> _ProbeResult:
    image_digest = engine.config.runtime.image_digest
    if type(image_digest) is not str:
        raise AssertionError("release image is not pinned")
    tool_version = _tool_version(
        algorithm=algorithm,
        corrupt_binding=corrupt_binding,
    )
    paths = engine.store.challenge_paths(state.identity)
    work = ensure_private_directory(
        paths.runtime / "forensic-readiness" / artifact_id
    )
    if any(work.iterdir()):
        raise AssertionError("readiness workspace was not fresh")
    client = engine.sandbox(
        state,
        workspace_override=work,
        challenge_dir_override=engine.challenge_input(state.identity),
        network_policy_override=NetworkPolicy.deny_all(),
    )
    if (
        client.backend.image_digest != image_digest
        or client.backend.network_policy.allow_targets
    ):
        raise AssertionError("readiness sandbox was not pinned deny-all")
    client.initialize_workspace()
    argv = list(
        _command_template(
            algorithm=algorithm,
            image_digest=image_digest,
            tool_version=tool_version,
            corrupt_binding=False,
        )[:-6]
    )
    if corrupt_binding:
        argv.append("--corrupt-binding")
    argv.extend(("--probe", "readiness.json"))
    result = client.run(
        CommandSpec(
            argv=tuple(argv),
            timeout_seconds=60,
            summary_bytes=0,
            network_target=None,
            resource_request=ResourceVector(
                cpu=1,
                memory_mib=512,
                network=0,
            ),
            deadline_monotonic_seconds=time.monotonic() + 120,
        )
    )
    if (
        result.status != "completed"
        or result.exit_code != 0
        or result.timed_out
        or result.orchestration_error is not None
    ):
        raise AssertionError(
            "real-Docker readiness probe failed: "
            f"{result.status}/{result.exit_code}/"
            f"{result.stderr_summary[:512]}"
        )
    reference = client.register_artifact(
        "readiness.json",
        maximum_bytes=READINESS_MAX_BYTES,
    )
    if reference.scope_fingerprint != client.scope_fingerprint:
        raise AssertionError("readiness artifact changed sandbox scope")
    payload = read_bounded_regular(
        work,
        reference.locator,
        maximum_bytes=READINESS_MAX_BYTES,
        expected_sha256=reference.sha256,
        expected_size=reference.size_bytes,
    )
    try:
        probe = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError("readiness probe did not emit JSON") from error
    expected_fixture = (
        FIXTURE_SOURCE
        if algorithm == "descriptor"
        else PERL_FIXTURE_SOURCE
    )
    expected_executable = (
        "/usr/bin/python3"
        if algorithm == "descriptor"
        else "/usr/bin/perl"
    )
    if (
        payload != _canonical(probe)
        or probe.get("protocol") != TOOL_PROTOCOL
        or probe.get("algorithm") != algorithm
        or probe.get("binding_mode")
        != ("pointer_mismatch" if corrupt_binding else "exact")
        or probe.get("fixture_sha256")
        != _sha256(expected_fixture.read_bytes())
        or probe.get("image_digest") != image_digest
        or probe.get("network") != "none"
        or probe.get("producer_executable") != expected_executable
        or probe.get("producer_executable_sha256") != tool_version
        or probe.get("tool_version_sha256") != tool_version
    ):
        raise AssertionError("readiness probe binding was invalid")
    relative = f"artifacts/forensic-readiness/{artifact_id}.json"
    destination = paths.root / relative
    atomic_write_bytes(destination, payload, mode=0o400)
    readiness = ForensicToolReadiness(
        tool_id=tool_id,
        independence_family=family,
        tool_version_sha256=tool_version,
        runtime_image_digest=image_digest,
        supported_pointer_kinds=("file_range",),
        command_template=_command_template(
            algorithm=algorithm,
            image_digest=image_digest,
            tool_version=tool_version,
            corrupt_binding=corrupt_binding,
        ),
        readiness_generation=1,
        readiness_artifact_id=artifact_id,
        readiness_artifact_sha256=_sha256(payload),
        readiness_artifact_size_bytes=len(payload),
    )
    artifact = ArtifactReference(
        id=artifact_id,
        path=relative,
        sha256=_sha256(payload),
        size=len(payload),
        media_type="application/json",
        extra={},
    )
    return _ProbeResult(
        readiness=readiness,
        artifact=artifact,
        algorithm=algorithm,
        corrupt_binding=corrupt_binding,
    )


def _install_readiness(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    state,
    groups: tuple[tuple[_ProbeResult, ...], ...],
):
    artifacts: list[ArtifactReference] = []
    for group in groups:
        readiness = tuple(
            sorted(
                (item.readiness for item in group),
                key=lambda item: item.tool_id,
            )
        )
        registry_sha256 = forensic_tool_readiness_registry_sha256(
            readiness
        )
        for item in group:
            artifact = copy.deepcopy(item.artifact)
            artifact.extra = {
                "context_visibility": "engine_private",
                "forensic_assertion_readiness": {
                    "configuration_epoch": state.configuration_epoch,
                    "confirmed": True,
                    "protocol": (
                        assertion_hotpath
                        .FORENSIC_ASSERTION_READINESS_PROTOCOL
                    ),
                    "readiness_registry_sha256": registry_sha256,
                    "schema_version": 1,
                    "tool": item.readiness.to_dict(),
                },
            }
            artifacts.append(artifact)

    def apply(current) -> None:
        current.artifacts.extend(copy.deepcopy(artifacts))

    return engine.store.update(
        identity,
        apply,
        expected_revision=state.revision,
    )


def _operator_document(
    *,
    index_execution,
    sources,
    readiness: tuple[ForensicToolReadiness, ...],
    pointer: ForensicFileRangePointer,
    assertion: ForensicAssertionNode,
) -> tuple[bytes, str]:
    selected = tuple(sorted(readiness, key=lambda item: item.tool_id))
    registry_sha256 = forensic_tool_readiness_registry_sha256(
        selected
    )
    graph = build_forensic_assertion_graph_plan(
        index_execution=index_execution,
        expected_sources=sources,
        tools=tuple(item.tool_binding for item in selected),
        pointers=(pointer,),
        assertions=(assertion,),
    )
    document = {
        "assertions": [assertion.to_dict()],
        "coverage_threshold_ppm": FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
        "index_root": graph.inventory_root.to_dict(),
        "pointers": [pointer.to_dict()],
        "protocol": FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
        "readiness_registry_sha256": registry_sha256,
        "schema_version": 1,
        "source_catalog_sha256": graph.source_catalog_sha256,
        "tools": [item.to_dict() for item in selected],
    }
    return _canonical(document), graph.plan_sha256


def _write_operator_spec(
    engine: ChallengeEngine,
    state,
    *,
    locator: str,
    payload: bytes,
) -> None:
    workspace = engine._workspace(state)
    destination = workspace / locator
    destination.write_bytes(payload)
    destination.chmod(0o400)


def _reload_verified_state(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    committed_revision: int,
):
    state = engine.store.load(identity, recover=False)
    state.validate()
    validate_forensic_assertion_state_graph(state)
    verified = engine.store.verify_artifacts(identity)
    if (
        state.revision != committed_revision
        or set(verified) != {item.id for item in state.artifacts}
    ):
        raise AssertionError(
            "Forensic StateStore reload or artifact validation failed"
        )
    return state


def _physical_assertion_execution(
    engine: ChallengeEngine,
    state,
    evaluation,
) -> tuple[int, tuple[str, ...]]:
    """Reconstruct one proof wave from physical state and sidecar bytes."""

    attempts = state.extra.get("forensic_assertion_preissues")
    matches = [
        item
        for item in attempts.values()
        if (
            type(item) is dict
            and type(item.get("terminal")) is dict
            and item["terminal"].get("evaluation_sha256")
            == evaluation.sha256
        )
    ] if type(attempts) is dict else []
    if len(matches) != 1:
        raise AssertionError("Forensic terminal attempt is not unique")
    attempt = matches[0]
    execution_plan = attempt.get("execution_plan")
    request_states = attempt.get("requests")
    plan_requests = (
        execution_plan.get("requests")
        if type(execution_plan) is dict
        else None
    )
    if (
        type(plan_requests) is not list
        or type(request_states) is not list
        or len(plan_requests) != len(request_states)
        or not plan_requests
        or attempt.get("status") != "completed"
    ):
        raise AssertionError("Forensic physical request wave is incomplete")
    root = engine.store.challenge_paths(state.identity).root
    artifacts = {item.id: item for item in state.artifacts}
    runs = {item.id: item for item in state.runs}
    if len(artifacts) != len(state.artifacts) or len(runs) != len(state.runs):
        raise AssertionError("Forensic physical state identities are reused")
    records = {item.request_id: item for item in evaluation.records}
    if (
        len(records) != len(evaluation.records)
        or any(
            request_id
            not in {
                item.get("request_id")
                for item in plan_requests
                if type(item) is dict
            }
            for request_id in records
        )
        or (evaluation.confirmed and len(records) != len(plan_requests))
    ):
        raise AssertionError("Forensic evaluation record set is incomplete")
    physical_versions: set[str] = set()
    for ordinal, (planned, request_state) in enumerate(
        zip(
            plan_requests,
            request_states,
            strict=True,
        ),
        start=1,
    ):
        record = (
            records.get(planned.get("request_id"))
            if type(planned) is dict
            else None
        )
        request_id = (
            planned.get("request_id")
            if type(planned) is dict
            else None
        )
        run_id = planned.get("run_id") if type(planned) is dict else None
        request_path = (
            planned.get("request_path")
            if type(planned) is dict
            else None
        )
        request_sha256 = (
            planned.get("request_sha256")
            if type(planned) is dict
            else None
        )
        if (
            type(planned) is not dict
            or type(request_state) is not dict
            or request_state.get("status") != "captured"
            or request_state.get("run_id") != run_id
            or request_state.get("request", {}).get("request_id")
            != request_id
            or request_state.get("request", {}).get("sha256")
            != request_sha256
            or (
                record is not None
                and (
                    record.run_id != run_id
                    or record.request_path != request_path
                    or record.request_sha256 != request_sha256
                )
            )
        ):
            raise AssertionError(
                f"Forensic physical request {ordinal} is not bound"
            )
        request_document = dict(planned)
        request_document.pop("request_sha256")
        request_payload = _read_unreferenced(
            root,
            request_path,
            maximum_bytes=256 * 1024,
        )
        if request_payload != _canonical(request_document):
            raise AssertionError(
                f"Forensic physical request {ordinal} changed"
            )
        request_artifact = artifacts.get(request_id)
        if (
            request_artifact is None
            or request_artifact.path != request_path
            or request_artifact.sha256 != request_sha256
            or request_artifact.size != len(request_payload)
        ):
            raise AssertionError(
                f"Forensic physical request {ordinal} artifact changed"
            )
        capture = request_state.get("capture")
        if type(capture) is not dict:
            raise AssertionError(
                f"Forensic physical capture {ordinal} is absent"
            )
        expected_result = {
            "artifact": capture.get("artifact"),
            "observation": capture.get("observation"),
            "protocol": (
                assertion_hotpath.FORENSIC_ASSERTION_HOTPATH_PROTOCOL
            ),
            "request_id": request_id,
            "run_id": run_id,
            "sandbox": capture.get("sandbox"),
        }
        result_path = (
            f"runs/{run_id}/forensic-assertion/result.json"
        )
        validation_path = (
            f"runs/{run_id}/forensic-assertion/validation.json"
        )
        result_payload = _read_unreferenced(
            root,
            result_path,
            maximum_bytes=64 * 1024,
        )
        validation_payload = _read_unreferenced(
            root,
            validation_path,
            maximum_bytes=64 * 1024,
        )
        try:
            result = strict_json_loads(result_payload)
            validation = strict_json_loads(validation_payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise AssertionError(
                f"Forensic physical sidecar {ordinal} is not JSON"
            ) from error
        expected_validation = {
            "network": "none",
            "ok": True,
            "protocol": (
                assertion_hotpath.FORENSIC_ASSERTION_HOTPATH_PROTOCOL
            ),
            "request_sha256": request_sha256,
            "workspace": "fresh",
        }
        run = runs.get(run_id)
        if (
            result != expected_result
            or result_payload != canonical_json_bytes(result)
            or type(result.get("sandbox")) is not dict
            or set(result["sandbox"])
            != {"duration_ms", "exit_code", "status", "timed_out"}
            or type(result["sandbox"].get("duration_ms")) is not int
            or result["sandbox"].get("duration_ms", -1) < 0
            or result["sandbox"].get("exit_code") != 0
            or result["sandbox"].get("status") != "completed"
            or result["sandbox"].get("timed_out") is not False
            or validation != expected_validation
            or validation_payload != canonical_json_bytes(validation)
            or (
                record is not None
                and (
                    run is None
                    or run.status.value != "completed"
                    or run.result_path != result_path
                    or run.validation_path != validation_path
                )
            )
            or (record is None and run is not None)
        ):
            raise AssertionError(
                f"Forensic physical sidecar {ordinal} is not successful"
            )
        captures = (
            (
                planned["observation"]["observation_id"],
                capture["observation"]["path"],
                capture["observation"]["sha256"],
                capture["observation"]["size_bytes"],
                1024 * 1024,
            ),
            (
                planned["artifact"]["artifact_id"],
                capture["artifact"]["path"],
                capture["artifact"]["sha256"],
                capture["artifact"]["size_bytes"],
                16 * 1024 * 1024,
            ),
        )
        for artifact_id, path, sha256, size_bytes, maximum in captures:
            try:
                read_bounded_regular(
                    root,
                    path,
                    maximum_bytes=maximum,
                    expected_sha256=sha256,
                    expected_size=size_bytes,
                )
            except (OSError, ValueError) as error:
                raise AssertionError(
                    f"Forensic physical capture {ordinal} changed"
                ) from error
            artifact = artifacts.get(artifact_id)
            if record is not None and (
                artifact is None
                or artifact.path != path
                or artifact.sha256 != sha256
                or artifact.size != size_bytes
                or artifact.source_run_id != run_id
            ):
                raise AssertionError(
                    f"Forensic physical capture {ordinal} is not state-bound"
                )
            if record is None and artifact is not None:
                raise AssertionError(
                    f"Forensic rejected capture {ordinal} gained authority"
                )
        physical_versions.add(planned["tool"]["tool_version_sha256"])

    expected_ids = attempt.get("expected_state_ids")
    evaluation_artifact = (
        artifacts.get(expected_ids.get("evaluation_artifact_id"))
        if type(expected_ids) is dict
        else None
    )
    if (
        evaluation_artifact is None
        or evaluation_artifact.sha256 != evaluation.sha256
        or evaluation_artifact.size != len(evaluation.canonical_bytes)
        or read_bounded_regular(
            root,
            evaluation_artifact.path,
            maximum_bytes=8 * 1024 * 1024,
            expected_sha256=evaluation_artifact.sha256,
            expected_size=evaluation_artifact.size,
        )
        != evaluation.canonical_bytes
    ):
        raise AssertionError("Forensic physical evaluation changed")
    if evaluation.confirmed and physical_versions != {
        PYTHON_EXECUTABLE_SHA256,
        PERL_EXECUTABLE_SHA256,
    }:
        raise AssertionError(
            "Forensic confirmation lacks two executable versions"
        )
    return len(plan_requests), tuple(sorted(physical_versions))


def _artifact_documents(
    engine: ChallengeEngine,
    state,
    evaluation,
    *,
    expected_secret: bytes,
    expected_pointer_sha256: str,
) -> list[dict[str, object]]:
    root = engine.store.challenge_paths(state.identity).root
    documents: list[dict[str, object]] = []
    families: set[str] = set()
    semantic = evaluation.semantic_evaluation
    versions = (
        {
            record.tool_version_sha256
            for record in semantic.corroboration_records
        }
        if semantic is not None
        else set()
    )
    for record in evaluation.records:
        if (
            record.pointer_sha256 != expected_pointer_sha256
            or record.pointer_id != "PTR-release-private-range"
        ):
            raise AssertionError("execution record pointer rebound")
        artifact = next(
            item
            for item in state.artifacts
            if item.id == record.artifact.artifact_id
        )
        payload = read_bounded_regular(
            root,
            artifact.path,
            maximum_bytes=256 * 1024,
            expected_sha256=artifact.sha256,
            expected_size=int(artifact.size),
        )
        document = json.loads(payload)
        if (
            payload != _canonical(document)
            or bytes.fromhex(document["range_hex"]) != expected_secret
            or document["range_sha256"] != _sha256(expected_secret)
            or document["offset_bytes"] != len(EVIDENCE_PREFIX)
            or document["length_bytes"] != len(expected_secret)
        ):
            raise AssertionError("private tool artifact range was incorrect")
        families.add(record.independence_family)
        documents.append(document)
        run = next(item for item in state.runs if item.id == record.run_id)
        validation = json.loads(
            _read_unreferenced(
                root,
                run.validation_path,
                maximum_bytes=64 * 1024,
            )
        )
        if validation.get("network") != "none":
            raise AssertionError("assertion execution enabled network")
    if (
        len(documents) != 2
        or len(families) != 2
        or versions
        != {PYTHON_EXECUTABLE_SHA256, PERL_EXECUTABLE_SHA256}
        or {item["algorithm"] for item in documents}
        != {"descriptor", "perl-sysread"}
    ):
        raise AssertionError("two independent tool families did not execute")
    return documents


def _state_bytes(state) -> bytes:
    return _canonical(state.to_dict())


def _read_unreferenced(
    root: Path,
    locator: str,
    *,
    maximum_bytes: int,
) -> bytes:
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise AssertionError("unreferenced release bound is invalid")
    if type(locator) is not str:
        raise AssertionError("unreferenced release locator is invalid")
    relative = PurePosixPath(locator)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise AssertionError("unreferenced release locator is unsafe")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    directories: list[int] = []
    source: int | None = None
    try:
        directories.append(os.open(root, directory_flags))
        for component in relative.parts[:-1]:
            directories.append(
                os.open(
                    component,
                    directory_flags,
                    dir_fd=directories[-1],
                )
            )
        source = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=directories[-1],
        )
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > maximum_bytes
        ):
            raise AssertionError(
                "unreferenced release artifact exceeded its bound"
            )
        payload = bytearray()
        while True:
            block = os.read(
                source,
                min(64 * 1024, maximum_bytes - len(payload) + 1),
            )
            if not block:
                break
            payload.extend(block)
            if len(payload) > maximum_bytes:
                raise AssertionError(
                    "unreferenced release artifact exceeded its bound"
                )
        after = os.fstat(source)
        if (
            len(payload) != before.st_size
            or any(
                getattr(before, field) != getattr(after, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            )
        ):
            raise AssertionError(
                "unreferenced release artifact changed while reading"
            )
        return bytes(payload)
    except OSError as error:
        raise AssertionError(
            "unreferenced release artifact could not be read safely"
        ) from error
    finally:
        if source is not None:
            os.close(source)
        for descriptor in reversed(directories):
            os.close(descriptor)


def _require_raw_absent(
    engine: ChallengeEngine,
    state,
    secret: bytes,
) -> None:
    paths = engine.store.challenge_paths(state.identity)
    state_locator = paths.state.relative_to(paths.root).as_posix()
    on_disk = _read_unreferenced(
        paths.root,
        state_locator,
        maximum_bytes=MAX_CANONICAL_STATE_BYTES,
    )
    for payload in (_state_bytes(state), on_disk):
        if secret in payload or secret.hex().encode("ascii") in payload:
            raise AssertionError("raw selected bytes leaked into state.json")


def _run_release(
    root: Path,
    identity: ChallengeIdentity,
    image_digest: str,
    secret: bytes,
) -> dict[str, object]:
    engine = _engine(root, image_digest)
    if engine._sandbox_factory is not None:
        raise AssertionError("release proof refuses a fake sandbox")
    _copy_challenge_inputs(engine, identity, secret)
    state, index_execution = _execute_index(engine, identity)
    sources = assertion_hotpath._current_sources(engine, state)
    source = next(item for item in sources if item.path == "evidence.bin")
    pointer = ForensicFileRangePointer(
        pointer_id="PTR-release-private-range",
        source_path=source.path,
        source_sha256=source.sha256,
        offset_bytes=len(EVIDENCE_PREFIX),
        length_bytes=len(secret),
    )
    pointer_sha256 = forensic_evidence_pointer_sha256(pointer)
    assertion = ForensicAssertionNode(
        assertion_id="ASSERT-release-private-range",
        state=ForensicAssertionState.CONFIRMED,
        claim_kind="artifact_identity",
        claim_sha256=_sha256(
            b"release smoke exact private file-range assertion"
        ),
        depends_on=(),
        evidence_pointer_ids=(pointer.pointer_id,),
    )

    positive = (
        _probe_tool(
            engine,
            state,
            tool_id="release-descriptor-positive",
            family="family-python-pread",
            algorithm="descriptor",
            corrupt_binding=False,
            artifact_id="READY-release-descriptor-positive",
        ),
        _probe_tool(
            engine,
            state,
            tool_id="release-perl-positive",
            family="family-perl-sysread",
            algorithm="perl-sysread",
            corrupt_binding=False,
            artifact_id="READY-release-perl-positive",
        ),
    )
    control = (
        _probe_tool(
            engine,
            state,
            tool_id="release-descriptor-control",
            family="family-python-pread",
            algorithm="descriptor",
            corrupt_binding=False,
            artifact_id="READY-release-descriptor-control",
        ),
        _probe_tool(
            engine,
            state,
            tool_id="release-perl-control",
            family="family-perl-sysread",
            algorithm="perl-sysread",
            corrupt_binding=True,
            artifact_id="READY-release-perl-control",
        ),
    )
    state = _install_readiness(
        engine,
        identity,
        state,
        (positive, control),
    )
    positive_payload, positive_plan_sha256 = _operator_document(
        index_execution=index_execution,
        sources=sources,
        readiness=tuple(item.readiness for item in positive),
        pointer=pointer,
        assertion=assertion,
    )
    control_payload, control_plan_sha256 = _operator_document(
        index_execution=index_execution,
        sources=sources,
        readiness=tuple(item.readiness for item in control),
        pointer=pointer,
        assertion=assertion,
    )
    _write_operator_spec(
        engine,
        state,
        locator="forensic-positive.json",
        payload=positive_payload,
    )
    _write_operator_spec(
        engine,
        state,
        locator="forensic-control.json",
        payload=control_payload,
    )

    baseline_status = state.status
    baseline_candidates = len(state.candidates)
    baseline_submissions = len(state.submissions)
    assertion_fact_count = sum(
        "forensic_assertion_state" in item.extra
        for item in state.facts
    )
    assertion_progress_count = sum(
        "forensic_assertion_state" in item.extra
        for item in state.progress_markers
    )
    confirmed: list[dict[str, object]] = []
    for ordinal in range(1, POSITIVE_REPETITIONS + 1):
        committed, evaluation = engine.prove_forensic_assertion(
            identity,
            operator_spec_locator="forensic-positive.json",
            timeout_seconds=180,
        )
        state = _reload_verified_state(
            engine,
            identity,
            committed_revision=committed.revision,
        )
        (
            physical_record_count,
            physical_tool_versions,
        ) = _physical_assertion_execution(
            engine,
            state,
            evaluation,
        )
        if (
            not evaluation.confirmed
            or evaluation.reason_codes
            or evaluation.semantic_evaluation is None
            or not evaluation.semantic_evaluation.passed
        ):
            raise AssertionError(
                f"confirmed repetition {ordinal} was rejected"
            )
        documents = _artifact_documents(
            engine,
            state,
            evaluation,
            expected_secret=secret,
            expected_pointer_sha256=pointer_sha256,
        )
        current_facts = sum(
            "forensic_assertion_state" in item.extra
            for item in state.facts
        )
        current_progress = sum(
            "forensic_assertion_state" in item.extra
            for item in state.progress_markers
        )
        if (
            current_facts != assertion_fact_count + ordinal
            or current_progress != assertion_progress_count + ordinal
            or len(state.candidates) != baseline_candidates
            or len(state.submissions) != baseline_submissions
            or state.status is not baseline_status
        ):
            raise AssertionError("confirmed reduction widened authority")
        _require_raw_absent(engine, state, secret)
        confirmed.append(
            {
                "algorithms": sorted(
                    str(item["algorithm"]) for item in documents
                ),
                "evaluation_sha256": evaluation.sha256,
                "ordinal": ordinal,
                "record_count": physical_record_count,
                "tool_version_sha256s": list(physical_tool_versions),
            }
        )

    before_control_facts = len(state.facts)
    before_control_progress = len(state.progress_markers)
    committed, rejected = engine.prove_forensic_assertion(
        identity,
        operator_spec_locator="forensic-control.json",
        timeout_seconds=180,
    )
    state = _reload_verified_state(
        engine,
        identity,
        committed_revision=committed.revision,
    )
    (
        control_record_count,
        control_tool_versions,
    ) = _physical_assertion_execution(
        engine,
        state,
        rejected,
    )
    if (
        rejected.confirmed
        or not rejected.reason_codes
        or "observation_request_binding_mismatch"
        not in rejected.reason_codes[0]
        or len(state.facts) != before_control_facts
        or len(state.progress_markers) != before_control_progress
        or len(state.candidates) != baseline_candidates
        or len(state.submissions) != baseline_submissions
        or state.status is not baseline_status
        or control_record_count != 2
    ):
        raise AssertionError("nonmatching control did not fail closed")
    attempts = state.extra.get("forensic_assertion_preissues")
    control_attempt = next(
        item
        for item in attempts.values()
        if (
            type(item) is dict
            and type(item.get("terminal")) is dict
            and item["terminal"].get("evaluation_sha256")
            == rejected.sha256
        )
    )
    if (
        control_attempt["terminal"]["reason_code"]
        != "forensic_assertion_rejected"
        or len(control_attempt["requests"]) != 2
        or any(
            request["status"] != "captured"
            for request in control_attempt["requests"]
        )
    ):
        raise AssertionError("control did not execute both Docker tools")
    control_algorithms: set[str] = set()
    root_path = engine.store.challenge_paths(identity).root
    for request in control_attempt["requests"]:
        capture = request["capture"]["artifact"]
        payload = read_bounded_regular(
            root_path,
            capture["path"],
            maximum_bytes=256 * 1024,
            expected_sha256=capture["sha256"],
            expected_size=capture["size_bytes"],
        )
        document = json.loads(payload)
        if bytes.fromhex(document["range_hex"]) != secret:
            raise AssertionError("control tool did not read the exact range")
        control_algorithms.add(document["algorithm"])
    if control_algorithms != {"descriptor", "perl-sysread"}:
        raise AssertionError("control did not run both tool families")
    _require_raw_absent(engine, state, secret)

    assertion_facts = [
        item
        for item in state.facts
        if "forensic_assertion_state" in item.extra
    ]
    assertion_progress = [
        item
        for item in state.progress_markers
        if "forensic_assertion_state" in item.extra
    ]
    if (
        len(assertion_facts) != POSITIVE_REPETITIONS
        or len(assertion_progress) != POSITIVE_REPETITIONS
    ):
        raise AssertionError("Fact/Progress count did not match confirmations")
    return {
        "assertion_facts": len(assertion_facts),
        "assertion_progress": len(assertion_progress),
        "candidates": len(state.candidates),
        "confirmed": confirmed,
        "control": {
            "algorithms": sorted(control_algorithms),
            "confirmed": rejected.confirmed,
            "reason_codes": list(rejected.reason_codes),
            "tool_version_sha256s": list(control_tool_versions),
        },
        "index_execution_sha256": index_execution.sha256,
        "network": "none",
        "operator_plans": {
            "control": control_plan_sha256,
            "positive": positive_plan_sha256,
        },
        "pointer": {
            **pointer.to_dict(),
            "sha256": pointer_sha256,
        },
        "readiness_probes": len(positive) + len(control),
        "state_status": state.status.value,
        "submissions": len(state.submissions),
        "tool_executables": {
            "family-perl-sysread": {
                "path": "/usr/bin/perl",
                "sha256": PERL_EXECUTABLE_SHA256,
            },
            "family-python-pread": {
                "path": "/usr/bin/python3",
                "sha256": PYTHON_EXECUTABLE_SHA256,
            },
        },
    }


def main() -> int:
    supplied = validate_image_digest(_parse_args().image_digest)
    if supplied != RELEASE_IMAGE_DIGEST:
        raise AssertionError("release proof refuses a different image digest")
    capabilities = inspect_pinned_capabilities(supplied)
    if capabilities.get("ok") is not True:
        raise AssertionError(
            "release image capability readiness failed: "
            + json.dumps(capabilities, sort_keys=True)
        )
    identity = ChallengeIdentity(
        "release-smoke",
        "forensics",
        "assertion-" + secrets.token_hex(8),
    )
    if _challenge_containers(identity):
        raise AssertionError("unique release identity already has containers")
    secret = (
        b"CTFOS_PRIVATE_RANGE_"
        + secrets.token_hex(16).encode("ascii")
    )
    summary: dict[str, object] | None = None
    cleanup_error: BaseException | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-forensic-assertion-hotpath-"
        ) as temporary:
            summary = _run_release(
                Path(temporary),
                identity,
                supplied,
                secret,
            )
            lingering = _challenge_containers(identity)
            if lingering:
                raise AssertionError(
                    "production one-shot containers were not removed"
                )
    finally:
        lingering = _challenge_containers(identity)
        try:
            _remove_exact_containers(lingering)
        except BaseException as error:
            cleanup_error = error
    if cleanup_error is not None:
        raise RuntimeError("exact release container cleanup failed") from cleanup_error
    if _challenge_containers(identity):
        raise AssertionError("release containers remain after cleanup")
    if summary is None:
        raise AssertionError("release proof produced no summary")
    summary = {
        **summary,
        "cleanup": "verified",
        "image_digest": supplied,
        "ok": True,
        "sandbox": "production_real_docker",
    }
    print(
        json.dumps(
            summary,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
