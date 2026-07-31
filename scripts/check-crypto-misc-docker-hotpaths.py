#!/usr/bin/env python3
"""Exercise the Crypto and Misc ChallengeEngine hot paths in real Docker.

The release smoke is deliberately self-contained and local.  It opens one
temporary challenge per category, supplies one operator candidate, and invokes
the same public engine methods used by ``ctfos``.  No model API, remote target,
automatic challenge selection, or submission is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.codex import Role
from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.crypto_metamorphic import (
    CRYPTO_METAMORPHIC_PROOF_PROTOCOL,
)
from ctf_os.engine.managed_oracle_preissue import (
    MANAGED_ORACLE_PREISSUE_PROTOCOL,
    MANAGED_ORACLE_PREISSUE_STATE_KEY,
)
from ctf_os.images import validate_image_digest
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    FlagCandidate,
    RunStatus,
)
from ctf_os.sandbox.files import read_bounded_regular
from ctf_os.schema import STATE_SCHEMA_VERSION


RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338"
)
CRYPTO_CANDIDATE = "KCTF{docker-crypto-metamorphic-hotpath}"


def _rsa_parameter_document(
    *,
    modulus: int,
    exponent: int,
    plaintext: bytes,
    rounds: int,
) -> bytes:
    return (
        json.dumps(
            {
                "N": modulus,
                "ciphertexts": [
                    pow(value, exponent, modulus)
                    for value in plaintext
                ],
                "e": exponent,
                "rounds": rounds,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


CRYPTO_VARIANT_OUTPUT = (
    b"metamorphic-variant:"
    + b"x"
    * (
        len(CRYPTO_CANDIDATE.encode("utf-8"))
        - len(b"metamorphic-variant:")
    )
)
CRYPTO_ORIGINAL = _rsa_parameter_document(
    modulus=61 * 53,
    exponent=17,
    plaintext=CRYPTO_CANDIDATE.encode("utf-8"),
    rounds=1,
)
CRYPTO_VARIANT = _rsa_parameter_document(
    modulus=67 * 71,
    exponent=17,
    plaintext=CRYPTO_VARIANT_OUTPUT,
    rounds=2,
)

MISC_CANDIDATE = "KCTF{docker-misc-transform-hotpath}"
MISC_SOURCE = b"immutable misc docker input\n"
_CRYPTO_PROOF_RESULT_KEYS = frozenset(
    {
        "candidate",
        "failures",
        "passed",
        "policy_mode",
        "required_attempts",
        "run_ids",
        "source_manifest_sha256",
        "successful_attempts",
        "total_attempts",
    }
)
_CRYPTO_RUN_DOCUMENT_MAX_BYTES = 1_048_576


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require the Crypto 3+3 metamorphic gate and Misc transform DAG "
            "plus 3-replay oracle to pass through the real pinned image."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    return parser.parse_args()


def _engine(root: Path, image_digest: str) -> ChallengeEngine:
    return ChallengeEngine(
        root,
        config=EngineConfig(
            workspace_root=root,
            runtime=RuntimeConfig(
                image="ctf-os:core",
                image_digest=image_digest,
                network_default="none",
                command_timeout_s=60,
            ),
        ),
    )


def _add_candidate(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    candidate_id: str,
    value: str,
) -> None:
    def mutate(state) -> None:
        state.candidates.append(
            FlagCandidate(id=candidate_id, value=value)
        )

    engine.store.update(identity, mutate)


def _capability(_digest: str) -> dict[str, object]:
    return {"ok": True, "schema_version": 2, "capabilities": {}}


def _execute_managed_builder_action(
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
    *,
    action: dict[str, object],
    payloads: dict[str, bytes],
    extra_write_locators: tuple[str, ...] = (),
) -> tuple[object, object]:
    """Drive the real Builder publish/register/dispatch path without a model."""

    orchestrator = ManagedOrchestrator(
        engine,
        capability_probe=_capability,
    )
    _state, session_id = orchestrator._reserve_session(identity, None)
    _state, cycle = orchestrator._reserve_cycle(identity, session_id)
    _state, wave, role_runs = orchestrator._reserve_wave(
        identity,
        session_id,
        cycle.id,
        "attack",
    )
    builder_run_id = role_runs[Role.BUILDER]
    paths = engine.store.challenge_paths(identity)
    run_workspace = (
        engine.store.run_paths(identity, run_id=builder_run_id).root
        / "workspace"
    )
    run_workspace.mkdir(parents=True)
    snapshots = paths.artifacts / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)

    records: list[tuple[str, str, bytes, str]] = []
    for ordinal, (locator, payload) in enumerate(
        sorted(payloads.items()),
        start=1,
    ):
        staged = run_workspace / locator
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(payload)
        artifact_id = f"A-{builder_run_id}-release-{ordinal}"
        relative = f"artifacts/snapshots/{artifact_id}.bin"
        snapshot = paths.root / relative
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)
        records.append((artifact_id, relative, payload, locator))

    def seed(state) -> None:
        run = next(
            item for item in state.runs if item.id == builder_run_id
        )
        run.status = RunStatus.COMPLETED
        run.result_path = f"runs/{builder_run_id}/result.json"
        run.validation_path = f"runs/{builder_run_id}/validation.json"
        run.extra["semantic_merge"] = True
        for artifact_id, relative, payload, locator in records:
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=relative,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    source_run_id=builder_run_id,
                    size=len(payload),
                    extra={
                        "reported_locator": locator,
                        "purpose": "managed release gate input",
                    },
                )
            )

    engine.store.update(identity, seed)
    output_actions = [
        {
            "kind": "write_artifact",
            "description": "publish referenced deterministic tool",
            "artifact_path": locator,
        }
        for locator in extra_write_locators
    ]
    output_actions.append(action)
    result = SimpleNamespace(
        invocation=SimpleNamespace(
            role=Role.BUILDER,
            run_id=builder_run_id,
            contract_version=2,
        ),
        output={"hypotheses": [], "actions": output_actions},
        attempts=(SimpleNamespace(),),
    )
    publication = orchestrator._apply_builder_publishes(
        identity,
        wave,
        (result,),
    )
    if publication.rejection is not None:
        raise AssertionError(publication.rejection)
    registration = orchestrator._register_typed_gate_actions(
        identity,
        wave,
        (result,),
    )
    if (
        registration.rejection_code is not None
        or len(registration.experiment_ids) != 1
    ):
        raise AssertionError(
            registration.rejection_code or "typed gate was not registered"
        )
    experiment_id = registration.experiment_ids[0]
    orchestrator._mark_action_selection(
        identity,
        session_id,
        cycle.id,
        (experiment_id,),
    )
    final = orchestrator._execute_selected_actions(
        identity,
        (experiment_id,),
        record_stall=False,
    )
    experiment = next(
        item for item in final.experiments if item.id == experiment_id
    )
    return final, experiment


def _read_crypto_run_document(
    challenge_root: Path,
    locator: str | None,
    *,
    label: str,
) -> dict[str, object]:
    if type(locator) is not str or not locator:
        raise AssertionError(f"Crypto {label} path is absent")
    try:
        relative = Path(locator)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("run document path is not canonical")
        target = challenge_root.joinpath(*relative.parts)
        metadata = target.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 0
            or metadata.st_size > _CRYPTO_RUN_DOCUMENT_MAX_BYTES
        ):
            raise ValueError("run document is not a bounded regular file")
        observed = target.read_bytes()
        if len(observed) != metadata.st_size:
            raise ValueError("run document changed during inventory")
        payload = read_bounded_regular(
            challenge_root,
            locator,
            maximum_bytes=_CRYPTO_RUN_DOCUMENT_MAX_BYTES,
            expected_sha256=hashlib.sha256(observed).hexdigest(),
            expected_size=len(observed),
        )
        value = json.loads(payload)
    except (OSError, UnicodeError, ValueError) as error:
        raise AssertionError(
            f"Crypto {label} is not a bounded canonical JSON document"
        ) from error
    if type(value) is not dict:
        raise AssertionError(f"Crypto {label} is not an object")
    return value


def _validated_crypto_execution(
    final,
    candidate,
    binding: object,
    *,
    challenge_root: Path,
    image_digest: str,
) -> tuple[list[object], int]:
    """Cross-check the claimed ProofResult against six physical runs."""

    if type(binding) is not dict:
        raise AssertionError("Crypto proof binding is absent")
    proof_result = binding.get("proof_result")
    run_ids = binding.get("run_ids")
    if (
        type(proof_result) is not dict
        or frozenset(proof_result) != _CRYPTO_PROOF_RESULT_KEYS
        or type(run_ids) is not list
        or len(run_ids) != 6
        or len(set(run_ids)) != 6
        or any(type(run_id) is not str or not run_id for run_id in run_ids)
        or list(candidate.proof_run_ids) != run_ids
        or proof_result.get("run_ids") != run_ids
        or proof_result.get("passed") is not True
        or proof_result.get("candidate") != candidate.value
        or proof_result.get("policy_mode")
        != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
        or proof_result.get("source_manifest_sha256")
        != final.metadata.get("source_manifest_sha256")
        or proof_result.get("successful_attempts") != 6
        or proof_result.get("required_attempts") != 6
        or proof_result.get("total_attempts") != 6
        or proof_result.get("failures") != []
    ):
        raise AssertionError(
            "Crypto ProofResult does not describe six successful attempts"
        )

    runs_by_id = {
        item.id: item for item in final.runs if item.id in set(run_ids)
    }
    if len(runs_by_id) != 6:
        raise AssertionError("Crypto physical proof runs are incomplete")
    runs = [runs_by_id[run_id] for run_id in run_ids]
    plan_sha256 = binding.get("plan_sha256")
    for ordinal, run in enumerate(runs, start=1):
        if (
            run.status is not RunStatus.COMPLETED
            or run.role != "crypto_metamorphic_proof"
            or run.extra.get("crypto_metamorphic_protocol")
            != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            or run.extra.get("plan_sha256") != plan_sha256
            or run.extra.get("attempt_ordinal") != ordinal
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} is not completed and bound"
            )
        request = _read_crypto_run_document(
            challenge_root,
            run.request_path,
            label=f"run {ordinal} request",
        )
        result = _read_crypto_run_document(
            challenge_root,
            run.result_path,
            label=f"run {ordinal} result",
        )
        validation = _read_crypto_run_document(
            challenge_root,
            run.validation_path,
            label=f"run {ordinal} validation",
        )
        attempt = request.get("attempt")
        observation = result.get("observation")
        if (
            request.get("kind") != "crypto_metamorphic_proof"
            or request.get("candidate_id") != candidate.id
            or request.get("protocol")
            != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            or request.get("plan_sha256") != plan_sha256
            or request.get("network_target") is not None
            or request.get("image_reference") != image_digest
            or request.get("source_manifest_sha256")
            != final.metadata.get("source_manifest_sha256")
            or type(attempt) is not dict
            or attempt.get("ordinal") != ordinal
            or result.get("status") != "completed"
            or result.get("exit_code") != 0
            or result.get("timed_out") is not False
            or type(observation) is not dict
            or observation.get("run_id") != run.id
            or observation.get("ordinal") != ordinal
            or observation.get("capture_complete") is not True
            or observation.get("truncation_known") is not True
            or observation.get("truncated") is not False
            or observation.get("timed_out") is not False
            or observation.get("orchestration_status") != "completed"
            or observation.get("runner_exit_code") != 0
            or observation.get("ctfwrap_exit_code") != 0
            or validation.get("ok") is not True
            or validation.get("protocol")
            != CRYPTO_METAMORPHIC_PROOF_PROTOCOL
            or validation.get("plan_sha256") != plan_sha256
            or validation.get("attempt_ordinal") != ordinal
        ):
            raise AssertionError(
                f"Crypto physical run {ordinal} evidence is not successful"
            )
    return runs, int(proof_result["successful_attempts"])


def _crypto(
    root: Path,
    image_digest: str,
    *,
    runtime: str,
) -> dict[str, object]:
    if runtime not in {"python", "sage"}:
        raise ValueError("release smoke runtime must be python or sage")
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "crypto",
        f"metamorphic-hotpath-{runtime}",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "task.py").write_text(
        "N = 3233\nciphertext = 2790\ne = 17\n",
        encoding="utf-8",
    )
    state = engine.add_challenge(
        identity,
        prompt="release smoke only",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    workspace = engine._workspace(state)
    (workspace / "solver.py").write_text(
        "import json, math, pathlib, sys\n"
        "data = json.loads(pathlib.Path(sys.argv[1]).read_text())\n"
        "n = data['N']\n"
        "p = next(v for v in range(2, math.isqrt(n) + 1) "
        "if n % v == 0)\n"
        "q = n // p\n"
        "d = pow(data['e'], -1, (p - 1) * (q - 1))\n"
        "plain = bytes(pow(v, d, n) for v in data['ciphertexts'])\n"
        "sys.stdout.buffer.write(plain)\n",
        encoding="utf-8",
    )
    (workspace / "original.json").write_bytes(CRYPTO_ORIGINAL)
    payloads = {
        "solver.py": (workspace / "solver.py").read_bytes(),
        "original.json": (workspace / "original.json").read_bytes(),
    }
    with tempfile.TemporaryDirectory(
        prefix="ctfos-release-operator-crypto-"
    ) as operator_temporary:
        operator_root = Path(operator_temporary)
        variant_path = operator_root / "variant.json"
        expected_path = operator_root / "variant.out"
        variant_path.write_bytes(CRYPTO_VARIANT)
        expected_path.write_bytes(CRYPTO_VARIANT_OUTPUT)
        _state, preissue = engine.preissue_managed_crypto_oracle(
            identity,
            variant_parameters_path=variant_path,
            variant_expected_output_path=expected_path,
            mutation_id="release-smoke-rsa-parameter-variant",
        )
    (workspace / "solver.py").unlink()
    (workspace / "original.json").unlink()
    _add_candidate(
        engine,
        identity,
        candidate_id=f"C-crypto-docker-{runtime}",
        value=CRYPTO_CANDIDATE,
    )

    final, experiment = _execute_managed_builder_action(
        engine,
        identity,
        action={
            "kind": "prove_crypto_metamorphic",
            "description": "run the managed 3+3 metamorphic oracle",
            "candidate_id": f"C-crypto-docker-{runtime}",
            "solver_artifact_path": "solver.py",
            "original_parameters_artifact_path": "original.json",
            "oracle_preissue_id": preissue["preissue_id"],
            "runtime": runtime,
        },
        payloads=payloads,
    )
    candidate = next(
        item
        for item in final.candidates
        if item.id == f"C-crypto-docker-{runtime}"
    )
    binding = candidate.extra.get("crypto_metamorphic_proof")
    challenge_root = engine.store.challenge_paths(identity).root
    runs, successful_attempts = _validated_crypto_execution(
        final,
        candidate,
        binding,
        challenge_root=challenge_root,
        image_digest=image_digest,
    )
    preissue_state = final.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
        preissue["preissue_id"]
    ]
    if (
        not isinstance(binding, dict)
        or binding.get("passed") is not True
        or binding.get("oracle_authority")
        != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or experiment.result.get("passed") is not True
        or candidate.status is not CandidateStatus.READY_TO_SUBMIT
        or len(runs) != 6
        or preissue_state.get("status") != "consumed"
        or not preissue_state.get("consumed_by_builder_run_id")
        or not preissue_state.get("consumed_by_experiment_id")
        or final.submissions
    ):
        raise AssertionError(
            "Crypto ChallengeEngine Docker hot path did not prove 3+3"
        )
    return {
        "candidate_status": candidate.status.value,
        "network": "none",
        "one_shot_consumed": True,
        "oracle_authority": MANAGED_ORACLE_PREISSUE_PROTOCOL,
        "oracle_preissue_status": preissue_state["status"],
        "runtime": runtime,
        "runs": len(runs),
        "successful_attempts": successful_attempts,
        "submissions": len(final.submissions),
    }


def _misc(root: Path, image_digest: str) -> dict[str, object]:
    engine = _engine(root, image_digest)
    identity = ChallengeIdentity(
        "release-smoke",
        "misc",
        "transform-hotpath",
    )
    incoming = engine.challenge_input(identity)
    incoming.mkdir(parents=True)
    (incoming / "challenge.bin").write_bytes(MISC_SOURCE)
    state = engine.add_challenge(
        identity,
        prompt="release smoke only",
        state_schema_version=STATE_SCHEMA_VERSION,
    )
    workspace = engine._workspace(state)
    (workspace / "transform.py").write_text(
        "import pathlib, sys\n"
        f"expected = {MISC_SOURCE!r}\n"
        "if pathlib.Path(sys.argv[1]).read_bytes() != expected:\n"
        "    raise SystemExit(41)\n"
        f"sys.stdout.write({MISC_CANDIDATE!r})\n",
        encoding="utf-8",
    )
    verifier_bytes = (
        "import pathlib, sys\n"
        f"candidate = {MISC_CANDIDATE.encode('utf-8')!r}\n"
        f"source = {MISC_SOURCE!r}\n"
        "valid = (pathlib.Path(sys.argv[1]).read_bytes() == candidate "
        "and pathlib.Path(sys.argv[2]).read_bytes() == source)\n"
        "raise SystemExit(0 if valid else 42)\n",
    )
    verifier_bytes = "".join(verifier_bytes).encode("utf-8")
    dag_spec = (
        json.dumps(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "id": "original",
                        "locator": "challenge.bin",
                    }
                ],
                "steps": [
                    {
                        "id": "extract",
                        "parents": ["original"],
                        "tool_locator": "transform.py",
                    }
                ],
                "terminal_step_id": "extract",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    payloads = {
        "misc-spec.json": dag_spec,
        "transform.py": (workspace / "transform.py").read_bytes(),
    }
    with tempfile.TemporaryDirectory(
        prefix="ctfos-release-operator-misc-"
    ) as operator_temporary:
        verifier_path = Path(operator_temporary) / "verifier.py"
        verifier_path.write_bytes(verifier_bytes)
        _state, preissue = engine.preissue_managed_misc_oracle(
            identity,
            verifier_path=verifier_path,
            verifier_id="original-condition",
            oracle_id="release-smoke-oracle-v1",
        )
    (workspace / "transform.py").unlink()
    _add_candidate(
        engine,
        identity,
        candidate_id="C-misc-docker",
        value=MISC_CANDIDATE,
    )

    final, experiment = _execute_managed_builder_action(
        engine,
        identity,
        action={
            "kind": "evaluate_misc_transform",
            "description": "run the managed DAG and hidden original oracle",
            "candidate_id": "C-misc-docker",
            "spec_artifact_path": "misc-spec.json",
            "oracle_preissue_id": preissue["preissue_id"],
        },
        payloads=payloads,
        extra_write_locators=("transform.py",),
    )
    candidate = next(
        item
        for item in final.candidates
        if item.id == "C-misc-docker"
    )
    binding = candidate.extra.get("misc_transform_evidence")
    run_ids = (
        binding.get("run_ids")
        if isinstance(binding, dict)
        else None
    )
    evaluation_id = (
        binding.get("misc_evaluation_id")
        if isinstance(binding, dict)
        else None
    )
    physical_runs = [
        item
        for item in final.runs
        if item.extra.get("misc_evaluation_id") == evaluation_id
    ]
    control_run_ids = (
        binding.get("oracle_control_run_ids")
        if isinstance(binding, dict)
        else None
    )
    preissue_state = final.extra[MANAGED_ORACLE_PREISSUE_STATE_KEY][
        preissue["preissue_id"]
    ]
    phases = [
        item.extra.get("phase")
        for item in physical_runs
    ]
    physical_details: list[dict[str, object]] = []
    challenge_root = engine.store.challenge_paths(identity).root
    for item in physical_runs:
        result_payload: dict[str, object] = {}
        if item.result_path:
            loaded = json.loads(
                (challenge_root / item.result_path).read_text(
                    encoding="utf-8"
                )
            )
            if isinstance(loaded, dict):
                result_payload = loaded
        physical_details.append(
            {
                "exit_code": result_payload.get("exit_code"),
                "phase": item.extra.get("phase"),
                "run_status": item.status.value,
                "sandbox_status": result_payload.get("status"),
                "timed_out": result_payload.get("timed_out"),
            }
        )
    checks = {
        "binding": isinstance(binding, dict),
        "binding_passed": (
            isinstance(binding, dict)
            and binding.get("passed") is True
        ),
        "managed_authority": (
            isinstance(binding, dict)
            and binding.get("oracle_authority")
            == MANAGED_ORACLE_PREISSUE_PROTOCOL
        ),
        "negative_control": (
            isinstance(binding, dict)
            and binding.get("oracle_control_status") == "passed"
            and binding.get("oracle_negative_control_passed") is True
        ),
        "one_control_run": (
            isinstance(control_run_ids, list)
            and len(control_run_ids) == 1
        ),
        "experiment_passed": experiment.result.get("passed") is True,
        "candidate_only": (
            candidate.status is CandidateStatus.OBSERVED_CANDIDATE
            and not candidate.proof_run_ids
        ),
        "logical_runs": (
            isinstance(run_ids, list)
            and len(run_ids) == 4
        ),
        "physical_runs": len(physical_runs) == 5,
        "transform_runs": phases.count("transform") == 1,
        "control_runs": phases.count("oracle-control") == 1,
        "reverse_runs": phases.count("reverse") == 3,
        "preissue_consumed": (
            preissue_state.get("status") == "consumed"
            and bool(preissue_state.get("consumed_by_builder_run_id"))
            and bool(preissue_state.get("consumed_by_experiment_id"))
        ),
        "no_submissions": not final.submissions,
    }
    if not all(checks.values()):
        raise AssertionError(
            "Misc ChallengeEngine Docker hot path did not prove DAG+3: "
            + json.dumps(
                {
                    "checks": checks,
                    "logical_run_ids": run_ids,
                    "physical_runs": physical_details,
                },
                sort_keys=True,
            )
        )
    return {
        "candidate_only": True,
        "candidate_status": candidate.status.value,
        "network": "none",
        "one_shot_consumed": True,
        "oracle_authority": MANAGED_ORACLE_PREISSUE_PROTOCOL,
        "oracle_control_runs": len(control_run_ids),
        "oracle_preissue_status": preissue_state["status"],
        "runs": len(physical_runs),
        "submissions": len(final.submissions),
        "transform_evidence_passed": binding["passed"],
        "transform_runs": 1,
        "verification_runs": 3,
    }


def main() -> int:
    image_digest = validate_image_digest(_parse_args().image_digest)
    if image_digest != RELEASE_IMAGE_DIGEST:
        raise AssertionError(
            "release smoke requires the repository-pinned image digest"
        )
    readiness = inspect_pinned_capabilities(image_digest)
    if readiness.get("ok") is not True:
        raise AssertionError(
            "pinned image readiness failed: "
            + json.dumps(readiness, sort_keys=True)
        )
    with tempfile.TemporaryDirectory(
        prefix="ctfos-crypto-misc-docker-"
    ) as temporary:
        root = Path(temporary)
        crypto_python = _crypto(
            root / "crypto-python",
            image_digest,
            runtime="python",
        )
        crypto_sage = _crypto(
            root / "crypto-sage",
            image_digest,
            runtime="sage",
        )
        misc = _misc(root / "misc", image_digest)
    print(
        json.dumps(
            {
                "crypto": {
                    "python": crypto_python,
                    "sage": crypto_sage,
                },
                "image_digest": image_digest,
                "misc": misc,
                "ok": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
