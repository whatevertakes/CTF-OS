#!/usr/bin/env python3
"""Prove the engine-owned Pwn interaction gate in the release image.

This developer-only release check builds one local Pwn fixture, establishes
its typed crash/snapshot/IP-control parent through the production engine, and
then runs the public interaction hot path as three attacks plus three matched
controls in real, fresh, networkless Docker proof workspaces.  A second
attempt injects one exact preissue-snapshot mutation and must reopen as a
terminal failed StateStore graph without gaining authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_ID,
    PWN_INTERACTION_V1_CONTRACT_VERSION,
    PWN_INTERACTION_V1_PROTOCOL,
    PWN_INTERACTION_V1_SENTINEL_REF,
    parse_pwn_interaction_v1_recipe,
)
from ctf_os.engine.pwn_interaction_hotpath import (
    PWN_INTERACTION_PRODUCER_SHA256,
    PWN_INTERACTION_STATE_KEY,
    PwnInteractionHotPathError,
)
from ctf_os.engine.pwn_ip_control import (
    PwnIpControlResult,
    PwnIpControlStatus,
    pwn_ip_control_child_experiment_id,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    pwn_runtime_snapshot_child_experiment_id,
)
from ctf_os.images import validate_image_digest
from ctf_os.models import ExperimentStatus, RunStatus
from ctf_os.store import StateStore
from ctf_os.store.atomic import atomic_write_bytes
from tests import test_pwn_crash_execution as crash_execution
from tests import test_pwn_ip_control_lifecycle as ip_lifecycle


REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE_SOURCE = (
    REPOSITORY
    / "ctf-os-image"
    / "tests"
    / "fixtures"
    / "pwn-interaction-hotpath.c"
)
RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338"
)
INTERACTION_SENTINEL_PATH = (
    "/work/ctfos-pwn-interaction-sentinel-v1"
)
CONTROL_WIDTH_BYTES = 8
BASELINE_TARGET = 0x0000500012345678
_SYMBOL_LINE = re.compile(
    r"^(?P<address>[0-9a-fA-F]+) [Tt] emit_sentinel$"
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require the complete Pwn interaction 3+3 gate and its "
            "preissue-tamper control in the exact release image."
        )
    )
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: object) -> bytes:
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


def _compile_fixture(destination: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a host C compiler named cc is required")
    completed = subprocess.run(
        (
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-pie",
            "-no-pie",
            (
                '-DCTFOS_SENTINEL_PATH="'
                + INTERACTION_SENTINEL_PATH
                + '"'
            ),
            str(FIXTURE_SOURCE),
            "-o",
            str(destination),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "could not compile Pwn interaction fixture: "
            + completed.stderr[:4096].decode(
                "utf-8",
                errors="replace",
            )
        )
    destination.chmod(0o500)


def _symbol_address(binary: Path) -> int:
    tool = shutil.which("nm")
    if tool is None:
        raise RuntimeError("a host nm is required")
    completed = subprocess.run(
        (tool, "-n", "--defined-only", str(binary)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError("nm could not inspect the interaction fixture")
    matches = [
        int(match.group("address"), 16)
        for line in completed.stdout.splitlines()
        if (match := _SYMBOL_LINE.fullmatch(line)) is not None
    ]
    if len(matches) != 1 or not 0 < matches[0] < (1 << 47):
        raise RuntimeError("emit_sentinel has no unique canonical address")
    return matches[0]


def _recipe(effect_address: int) -> bytes:
    document = {
        "contract": {
            "id": PWN_INTERACTION_V1_CONTRACT_ID,
            "protocol": PWN_INTERACTION_V1_PROTOCOL,
            "version": PWN_INTERACTION_V1_CONTRACT_VERSION,
        },
        "effect": {
            "address_ref": "effect_address",
            "control_value": 0,
            "sentinel_ref": PWN_INTERACTION_V1_SENTINEL_REF,
            "success_stream": "stdout_or_stderr",
        },
        "schema_version": 1,
        "steps": [
            {
                "id": "set-effect",
                "name": "effect_address",
                "op": "set_u64",
                "value": effect_address,
            },
            {
                "id": "pack-effect",
                "name": "effect_bytes",
                "op": "pack_u64",
                "value": {"ref": "effect_address"},
            },
            {
                "id": "build-payload",
                "name": "payload",
                "op": "concat",
                "parts": [
                    {
                        "literal": {
                            "encoding": "hex",
                            "value": "41" * 17,
                        }
                    },
                    {"ref": "effect_bytes"},
                    {"ref": PWN_INTERACTION_V1_SENTINEL_REF},
                ],
            },
            {
                "id": "send-payload",
                "mode": "raw",
                "op": "send",
                "parts": [{"ref": "payload"}],
            },
            {"id": "close-stdin", "op": "shutdown_stdin"},
        ],
        "timeout_milliseconds": 30_000,
    }
    recipe = parse_pwn_interaction_v1_recipe(
        _canonical_bytes(document)
    )
    return recipe.canonical_bytes


def _typed_parent(state, parent_id: str) -> None:
    experiment = next(
        item for item in state.experiments if item.id == parent_id
    )
    if (
        experiment.status is not ExperimentStatus.COMPLETED
        or type(experiment.result) is not dict
    ):
        raise AssertionError("typed IP-control parent did not complete")
    result = PwnIpControlResult.from_dict(
        experiment.result["pwn_ip_control_evidence"]["result"]
    )
    if (
        result.status is not PwnIpControlStatus.PROVEN
        or not result.instruction_pointer_control_proven
    ):
        raise AssertionError("typed parent did not prove IP control")


def _attempt_runs(state, attempt: dict[str, object]):
    run_ids = [item["run_id"] for item in attempt["replays"]]
    return [
        next(run for run in state.runs if run.id == run_id)
        for run_id in run_ids
    ]


def main() -> int:
    supplied = validate_image_digest(_parse_args().image_digest)
    if supplied != RELEASE_IMAGE_DIGEST:
        raise AssertionError(
            "Pwn interaction release proof refuses a different image digest"
        )
    readiness = inspect_pinned_capabilities(supplied)
    if readiness.get("ok") is not True:
        raise AssertionError(
            "release image capability readiness failed: "
            + json.dumps(readiness, sort_keys=True)
        )

    with tempfile.TemporaryDirectory(
        prefix="ctfos-pwn-interaction-release-"
    ) as build_directory:
        compiled = Path(build_directory) / "challenge"
        _compile_fixture(compiled)
        source = compiled.read_bytes()
        source_sha256 = _sha256(source)
        effect_address = _symbol_address(compiled)
        recipe_bytes = _recipe(effect_address)

        lifecycle = ip_lifecycle.PwnIpControlLifecycleTests(
            methodName=(
                "test_confirmed_snapshot_proves_only_ip_control_in_three_replays"
            )
        )
        original_elf_factory = crash_execution._elf64_executable
        original_image_digest = crash_execution.IMAGE_DIGEST
        original_baseline = ip_lifecycle._BASELINE_RIP
        original_baseline_bytes = ip_lifecycle._BASELINE_RIP_BYTES
        crash_execution._elf64_executable = lambda: source
        crash_execution.IMAGE_DIGEST = supplied
        ip_lifecycle._BASELINE_RIP = BASELINE_TARGET
        ip_lifecycle._BASELINE_RIP_BYTES = BASELINE_TARGET.to_bytes(
            CONTROL_WIDTH_BYTES,
            "little",
        )
        lifecycle.setUp()
        try:
            (
                fixture,
                _registration_coordinator,
                engine,
                crash_id,
                _baseline_payload,
            ) = lifecycle._fixture()
            engine._sandbox_factory = None
            engine._capability_probe = inspect_pinned_capabilities
            engine._capability_probe_accepts_timeout = True

            crash_state = fixture._execute(engine, crash_id)
            crash = next(
                item
                for item in crash_state.experiments
                if item.id == crash_id
            )
            if (
                crash.status is not ExperimentStatus.KEPT
                or len(crash.evidence_run_ids) != 6
            ):
                raise AssertionError("real-Docker crash parent failed")
            snapshot_id = pwn_runtime_snapshot_child_experiment_id(
                crash_id
            )
            snapshot_state = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(snapshot_id,),
            )
            snapshot_state = (
                engine._advance_pwn_runtime_snapshot_disclosures(
                    fixture.identity
                )
            )
            snapshot_state = (
                engine._register_pwn_ip_control_child_if_applicable(
                    fixture.identity,
                    snapshot_state,
                )
            )
            parent_id = pwn_ip_control_child_experiment_id(snapshot_id)
            parent_state = engine.execute_registered_experiments(
                fixture.identity,
                maximum=1,
                _session_owned=True,
                experiment_ids=(parent_id,),
            )
            _typed_parent(parent_state, parent_id)

            workspace = engine._workspace(parent_state)
            recipe_path = workspace / "interaction-release.json"
            recipe_path.write_bytes(recipe_bytes)
            recipe_path.chmod(0o400)
            before = engine.store.load(fixture.identity)
            before_shape = {
                "candidates": len(before.candidates),
                "facts": len(before.facts),
                "progress": len(before.progress_markers),
                "status": before.status,
                "submissions": len(before.submissions),
            }
            final, evaluation = engine.prove_pwn_interaction(
                fixture.identity,
                parent_experiment_id=parent_id,
                recipe_locator="interaction-release.json",
                timeout_seconds=300,
            )
            passed_attempts = [
                item
                for item in final.extra[
                    PWN_INTERACTION_STATE_KEY
                ].values()
                if item["status"] == "passed"
            ]
            if len(passed_attempts) != 1:
                raise AssertionError("interaction success journal is missing")
            passed = passed_attempts[0]
            physical_identities = passed["proof_identities"]
            physical_tuples = {
                (
                    item["scope_fingerprint"],
                    item["sandbox_run_id"],
                    item["clean_prefix"],
                )
                for item in physical_identities
            }
            clean_prefixes = {
                item["clean_prefix"] for item in physical_identities
            }
            canonical_scope = passed[
                "canonical_scope_fingerprint"
            ]
            passed_runs = _attempt_runs(final, passed)
            passed_receipt_ids = {
                item["receipt_id"] for item in passed["replays"]
            }
            passed_receipts = [
                item
                for item in final.receipts
                if item.id in passed_receipt_ids
            ]
            preissued_before_first_run = (
                len(passed["replays"]) == 6
                and all(
                    engine.store.run_paths(
                        fixture.identity,
                        item["run_id"],
                    ).request.is_file()
                    for item in passed["replays"]
                )
            )
            sentinel_hashes = {
                item.sentinel_sha256
                for item in (
                    *evaluation.attack_receipts,
                    *evaluation.control_receipts,
                )
            }
            matched_terminal = all(
                (
                    attack.target_exit_code,
                    attack.target_signal,
                )
                == (
                    control.target_exit_code,
                    control.target_signal,
                )
                for attack, control in zip(
                    evaluation.attack_receipts,
                    evaluation.control_receipts,
                    strict=True,
                )
            )
            if (
                not evaluation.passed
                or len(physical_identities) != 6
                or len(physical_tuples) != 6
                or len(clean_prefixes) != 6
                or any(
                    item["scope_fingerprint"] != canonical_scope
                    for item in physical_identities
                )
                or len(passed_runs) != 6
                or any(
                    item.status is not RunStatus.COMPLETED
                    for item in passed_runs
                )
                or len(passed_receipts) != 6
                or not preissued_before_first_run
            ):
                raise AssertionError(
                    "real-Docker interaction transport was incomplete"
                )

            # Inject the failure only after the first post-preissue
            # capability check.  The first real Docker replay then runs and
            # the next drift guard must restore the exact engine-held bytes.
            probe_calls = 0
            real_probe = inspect_pinned_capabilities

            def tampering_probe(
                digest: str,
                *,
                timeout_seconds: int | float = 30,
            ):
                nonlocal probe_calls
                report = real_probe(
                    digest,
                    timeout_seconds=timeout_seconds,
                )
                probe_calls += 1
                if probe_calls == 2:
                    current = engine.store.load(fixture.identity)
                    candidates = [
                        item
                        for item in current.extra[
                            PWN_INTERACTION_STATE_KEY
                        ].values()
                        if item["status"] == "preissued"
                    ]
                    if len(candidates) != 1:
                        raise AssertionError(
                            "failure control cannot locate preissue"
                        )
                    attempt = candidates[0]
                    artifact = next(
                        item
                        for item in current.artifacts
                        if item.id
                        == attempt["preissue_artifact_id"]
                    )
                    atomic_write_bytes(
                        (
                            engine.store.challenge_paths(
                                fixture.identity
                            ).root
                            / artifact.path
                        ),
                        b'{"tampered":true}\n',
                        mode=0o400,
                    )
                return report

            failure_before = engine.store.load(fixture.identity)
            engine._capability_probe = tampering_probe
            try:
                engine.prove_pwn_interaction(
                    fixture.identity,
                    parent_experiment_id=parent_id,
                    recipe_locator="interaction-release.json",
                    timeout_seconds=300,
                )
            except PwnInteractionHotPathError as error:
                if error.code != (
                    "pwn_interaction_preissue_artifact_changed"
                ):
                    raise
            else:
                raise AssertionError(
                    "preissue SHA-256 tamper did not fail closed"
                )
            finally:
                engine._capability_probe = real_probe
            failed_state = engine.store.load(
                fixture.identity,
                recover=False,
            )
            failed_attempts = [
                item
                for item in failed_state.extra[
                    PWN_INTERACTION_STATE_KEY
                ].values()
                if item["status"] == "failed"
            ]
            if len(failed_attempts) != 1:
                raise AssertionError("failure control journal is missing")
            failed = failed_attempts[0]
            failed_runs = _attempt_runs(failed_state, failed)
            failed_receipt_ids = {
                item["receipt_id"] for item in failed["replays"]
            }
            failed_receipts = [
                item
                for item in failed_state.receipts
                if item.id in failed_receipt_ids
            ]
            reopened = StateStore(
                engine.store.workspace_root,
                max_artifact_bytes=engine.store.max_artifact_bytes,
            ).load(fixture.identity, recover=False)
            state_store_reopen_ok = (
                reopened.revision == failed_state.revision
            )
            if (
                failed["failure_code"]
                != "pwn_interaction_preissue_artifact_changed"
                or failed["terminal"] is not True
                or len(failed_runs) != 6
                or any(
                    item.status
                    not in {
                        RunStatus.COMPLETED,
                        RunStatus.INTERRUPTED,
                    }
                    for item in failed_runs
                )
                or len(failed_receipts) != 6
                or len(failed_state.facts)
                != len(failure_before.facts)
                or len(failed_state.progress_markers)
                != len(failure_before.progress_markers)
                or not state_store_reopen_ok
            ):
                raise AssertionError(
                    "preissue tamper did not terminalize exactly"
                )

            summary = {
                "authority": {
                    "auto_submit_authorized": False,
                    "candidates_added": (
                        len(final.candidates)
                        - before_shape["candidates"]
                    ),
                    "executed_fact_added": (
                        len(final.facts) - before_shape["facts"]
                    ),
                    "progress_added": (
                        len(final.progress_markers)
                        - before_shape["progress"]
                    ),
                    "status_changed": (
                        final.status is not before_shape["status"]
                    ),
                    "submissions_added": (
                        len(final.submissions)
                        - before_shape["submissions"]
                    ),
                },
                "bindings": {
                    "image_digest": supplied,
                    "preissue_sha256": passed["preissue_sha256"],
                    "producer_sha256": (
                        PWN_INTERACTION_PRODUCER_SHA256
                    ),
                    "recipe_sha256": passed["recipe_sha256"],
                    "source_sha256": passed["source"]["sha256"],
                },
                "evaluation": {
                    "attack_replays": len(
                        evaluation.attack_receipts
                    ),
                    "control_replays": len(
                        evaluation.control_receipts
                    ),
                    "matched_terminal": matched_terminal,
                    "passed": evaluation.passed,
                    "reason_code": evaluation.reason_code,
                    "sha256": passed["evaluation_sha256"],
                    "unique_sentinels": len(sentinel_hashes),
                },
                "failure_control": {
                    "candidates_added": (
                        len(failed_state.candidates)
                        - len(failure_before.candidates)
                    ),
                    "facts_added": (
                        len(failed_state.facts)
                        - len(failure_before.facts)
                    ),
                    "failure_mode": "preissue_sha256_tamper",
                    "progress_added": (
                        len(failed_state.progress_markers)
                        - len(failure_before.progress_markers)
                    ),
                    "receipts": len(failed_receipts),
                    "runs_terminal": len(failed_runs),
                    "state_store_reopen_ok": state_store_reopen_ok,
                    "status": failed["status"],
                    "submissions_added": (
                        len(failed_state.submissions)
                        - len(failure_before.submissions)
                    ),
                    "terminal": failed["terminal"],
                    "tested": True,
                },
                "image_digest": supplied,
                "network": "none",
                "ok": True,
                "parent": {
                    "authority": "typed_pwn_ip_control_v1",
                    "experiment_id": parent_id,
                    "fact_id": None,
                    "run_id": None,
                },
                "preissue": {
                    "preissued_before_first_run": (
                        preissued_before_first_run
                    ),
                    "replay_count": len(passed["replays"]),
                    "sha256": passed["preissue_sha256"],
                    "status": passed["status"],
                    "terminal": passed["terminal"],
                },
                "protocol": "ctfos.pwn.interaction.hotpath.v1",
                "sandbox": "production_real_docker",
                "source_challenge": {
                    "category": fixture.identity.category,
                    "challenge_id": fixture.identity.challenge_id,
                    "contest_id": fixture.identity.contest_id,
                    "source_sha256": source_sha256,
                },
                "transport": {
                    "canonical_scope_fingerprint": canonical_scope,
                    "fresh_clean_workspaces": 6,
                    "network_none": 6,
                    "one_shot": 6,
                    "physical_identities": physical_identities,
                    "proof_outputs_per_run": 4,
                    "unique_clean_prefix_count": len(
                        clean_prefixes
                    ),
                    "unique_proof_identity_count": len(
                        physical_tuples
                    ),
                },
            }
            if (
                summary["bindings"]["source_sha256"]
                != source_sha256
            ):
                raise AssertionError(
                    "release source binding differs from compiled ELF"
                )
            print(
                json.dumps(
                    summary,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        finally:
            lifecycle.doCleanups()
            lifecycle.tearDown()
            crash_execution._elf64_executable = original_elf_factory
            crash_execution.IMAGE_DIGEST = original_image_digest
            ip_lifecycle._BASELINE_RIP = original_baseline
            ip_lifecycle._BASELINE_RIP_BYTES = original_baseline_bytes
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
