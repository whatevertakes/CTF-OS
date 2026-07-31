#!/usr/bin/env python3
"""Run three independent real-Docker Pwn D/V/N/A/P/E release proofs."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from ctf_os.store.atomic import StrictJSONError, strict_json_loads


REPOSITORY = Path(__file__).resolve().parent.parent
SINGLE_PROOF = (
    REPOSITORY
    / "scripts"
    / "check-pwn-exploit-effect-hotpath-docker.py"
)
RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338"
)
REPETITIONS = 3
MAX_CHILD_STDOUT_BYTES = 2 * 1024 * 1024
MAX_CHILD_STDERR_BYTES = 256 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHILD_ROOT_KEYS = frozenset(
    {
        "candidates",
        "dependency",
        "effect",
        "evidence_execution",
        "fixture",
        "image_digest",
        "network",
        "ok",
        "setup_boundary",
        "submissions",
    }
)
_PHYSICAL_RECORD_KEYS = frozenset(
    {
        "artifact_count",
        "artifact_manifest_sha256",
        "clean_prefix",
        "clean_workspace",
        "network",
        "one_shot",
        "request_sha256",
        "result_sha256",
        "role",
        "run_id",
        "sandbox_method",
        "sandbox_run_id",
        "scope_fingerprint",
        "transport_receipt_sha256",
        "validation_sha256",
    }
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require three fresh 16-clean-proof Pwn dependency chains and "
            "three rehashed tamper-control rejections."
        )
    )
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
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
    ).hexdigest()


def _exact_mapping(
    value: object,
    required: frozenset[str] | set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(required):
        raise RuntimeError(f"{label} schema is invalid")
    return value


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _read_capture(
    stream,
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    size = os.fstat(stream.fileno()).st_size
    if size > maximum_bytes:
        raise RuntimeError(f"{label} exceeded its byte limit")
    stream.seek(0)
    payload = stream.read(maximum_bytes + 1)
    if len(payload) != size or len(payload) > maximum_bytes:
        raise RuntimeError(f"{label} changed while being read")
    return payload


def _validate_child_summary(
    value: object,
    *,
    digest: str,
    index: int,
) -> dict[str, object]:
    result = _exact_mapping(
        value,
        _CHILD_ROOT_KEYS,
        label=f"Pwn dependency repetition {index}",
    )
    dependency = _exact_mapping(
        result["dependency"],
        {
            "artifact_validation",
            "branch",
            "gate_route",
            "graph_id",
            "graph_sha256",
            "primitive_recomputed",
            "static_target_validation",
            "tamper_control_rejected",
        },
        label=f"Pwn dependency repetition {index} dependency",
    )
    artifact_validation = _exact_mapping(
        dependency["artifact_validation"],
        {
            "aggregate_commitment_sha256",
            "artifact_count",
            "descriptor_reread",
            "nofollow_required",
            "raw_output_returned",
            "total_bytes",
        },
        label=f"Pwn dependency repetition {index} artifact validation",
    )
    static_target = _exact_mapping(
        dependency["static_target_validation"],
        {
            "manifest_sha256",
            "raw_output_returned",
            "source_locator",
            "source_sha256",
            "source_size_bytes",
        },
        label=f"Pwn dependency repetition {index} static target",
    )
    effect = _exact_mapping(
        result["effect"],
        {"authorities", "child_experiment_id", "records"},
        label=f"Pwn dependency repetition {index} effect",
    )
    authorities = _exact_mapping(
        effect["authorities"],
        {
            "auto_submit_authorized",
            "exploit_effect_proven",
            "exploit_proven",
            "flag_proven",
            "primitive_proven",
            "proof_satisfied",
            "stage_advance_authorized",
        },
        label=f"Pwn dependency repetition {index} authorities",
    )
    evidence = _exact_mapping(
        result["evidence_execution"],
        {
            "crash_clean_proofs",
            "effect_clean_proofs",
            "ip_control_clean_proofs",
            "network_none",
            "physical_manifest_sha256",
            "physical_records",
            "runtime_snapshot_clean_proofs",
            "sandbox",
            "total_real_clean_proofs",
        },
        label=f"Pwn dependency repetition {index} physical evidence",
    )
    fixture = _exact_mapping(
        result["fixture"],
        {
            "baseline_target",
            "controlled_offset",
            "controlled_width_bytes",
            "emit_sentinel_address",
            "source_sha256",
        },
        label=f"Pwn dependency repetition {index} fixture",
    )
    records = evidence["physical_records"]
    effect_records = effect["records"]
    if (
        type(records) is not list
        or len(records) != 16
        or type(effect_records) is not list
        or len(effect_records) != 6
    ):
        raise RuntimeError(
            f"Pwn dependency repetition {index} evidence count is invalid"
        )
    role_counts = {
        "crash": 0,
        "runtime_snapshot": 0,
        "ip_control": 0,
        "effect": 0,
    }
    physical_run_ids: set[str] = set()
    physical_run_ids_by_role: dict[str, set[str]] = {
        role: set() for role in role_counts
    }
    effect_sandbox_ids: set[str] = set()
    effect_scopes: set[str] = set()
    effect_clean_prefixes: set[str] = set()
    for ordinal, raw in enumerate(records, start=1):
        record = _exact_mapping(
            raw,
            _PHYSICAL_RECORD_KEYS,
            label=(
                f"Pwn dependency repetition {index} physical "
                f"record {ordinal}"
            ),
        )
        role = record["role"]
        run_id = record["run_id"]
        if (
            role not in role_counts
            or type(run_id) is not str
            or not run_id
            or run_id in physical_run_ids
            or type(record["artifact_count"]) is not int
            or record["artifact_count"]
            != (3 if role == "effect" else 2)
            or not _valid_sha256(record["artifact_manifest_sha256"])
            or record["clean_workspace"] is not True
            or record["network"] != "none"
            or record["one_shot"] is not True
            or not _valid_sha256(record["request_sha256"])
            or not _valid_sha256(record["result_sha256"])
            or record["sandbox_method"] != "run_clean_proof"
            or not _valid_sha256(record["validation_sha256"])
        ):
            raise RuntimeError(
                f"Pwn dependency repetition {index} physical record "
                "is invalid"
            )
        physical_run_ids.add(run_id)
        role_counts[str(role)] += 1
        physical_run_ids_by_role[str(role)].add(run_id)
        if role == "effect":
            if (
                type(record["sandbox_run_id"]) is not str
                or not record["sandbox_run_id"]
                or type(record["clean_prefix"]) is not str
                or re.fullmatch(
                    r"clean-[0-9a-f]{12}",
                    record["clean_prefix"],
                )
                is None
                or not _valid_sha256(record["scope_fingerprint"])
                or not _valid_sha256(
                    record["transport_receipt_sha256"]
                )
            ):
                raise RuntimeError(
                    f"Pwn dependency repetition {index} effect "
                    "transport record is invalid"
                )
            effect_sandbox_ids.add(record["sandbox_run_id"])
            effect_scopes.add(record["scope_fingerprint"])
            effect_clean_prefixes.add(record["clean_prefix"])
        elif (
            record["clean_prefix"] is not None
            or record["sandbox_run_id"] is not None
            or record["scope_fingerprint"] is not None
            or record["transport_receipt_sha256"] is not None
        ):
            raise RuntimeError(
                f"Pwn dependency repetition {index} non-effect "
                "transport record widened"
            )
    expected_role_counts = {
        "crash": 6,
        "runtime_snapshot": 1,
        "ip_control": 3,
        "effect": 6,
    }
    if (
        role_counts != expected_role_counts
        or len(effect_clean_prefixes) != 6
        or not 1 <= len(effect_sandbox_ids) <= 6
        or len(effect_scopes) != 1
        or evidence["physical_manifest_sha256"]
        != _canonical_sha256(records)
    ):
        raise RuntimeError(
            f"Pwn dependency repetition {index} physical matrix is invalid"
        )
    effect_run_ids: set[str] = set()
    sentinel_hashes: set[str] = set()
    for ordinal, raw in enumerate(effect_records, start=1):
        record = _exact_mapping(
            raw,
            {
                "ordinal",
                "phase",
                "run_id",
                "sentinel_sha256",
                "status",
            },
            label=(
                f"Pwn dependency repetition {index} effect "
                f"record {ordinal}"
            ),
        )
        expected_phase = "positive" if ordinal <= 3 else "control"
        expected_ordinal = ordinal if ordinal <= 3 else ordinal - 3
        expected_status = (
            "effect_observed"
            if expected_phase == "positive"
            else "effect_absent"
        )
        if (
            type(record["ordinal"]) is not int
            or record["phase"] != expected_phase
            or record["ordinal"] != expected_ordinal
            or record["status"] != expected_status
            or type(record["run_id"]) is not str
            or record["run_id"] not in physical_run_ids
            or record["run_id"] in effect_run_ids
            or not _valid_sha256(record["sentinel_sha256"])
            or record["sentinel_sha256"] in sentinel_hashes
        ):
            raise RuntimeError(
                f"Pwn dependency repetition {index} effect matrix "
                "is invalid"
            )
        effect_run_ids.add(record["run_id"])
        sentinel_hashes.add(record["sentinel_sha256"])
    if (
        effect_run_ids != physical_run_ids_by_role["effect"]
        or result["ok"] is not True
        or result["image_digest"] != digest
        or result["network"] != "none"
        or type(result["candidates"]) is not int
        or result["candidates"] != 0
        or type(result["submissions"]) is not int
        or result["submissions"] != 0
        or dependency["branch"]
        != "DEPENDENCY_SCOPED_NOT_APPLICABLE"
        or dependency["gate_route"] != ["D", "V", "N/A", "P", "E"]
        or type(dependency["graph_id"]) is not str
        or not dependency["graph_id"]
        or not _valid_sha256(dependency["graph_sha256"])
        or dependency["primitive_recomputed"] is not True
        or dependency["tamper_control_rejected"] is not True
        or artifact_validation["descriptor_reread"] is not True
        or artifact_validation["nofollow_required"] is not True
        or artifact_validation["raw_output_returned"] is not False
        or not _valid_sha256(
            artifact_validation["aggregate_commitment_sha256"]
        )
        or type(artifact_validation["artifact_count"]) is not int
        or artifact_validation["artifact_count"] < 1
        or type(artifact_validation["total_bytes"]) is not int
        or artifact_validation["total_bytes"] < 1
        or static_target["raw_output_returned"] is not False
        or not _valid_sha256(static_target["manifest_sha256"])
        or static_target["source_locator"] != "challenge"
        or static_target["source_sha256"] != fixture["source_sha256"]
        or not _valid_sha256(static_target["source_sha256"])
        or type(static_target["source_size_bytes"]) is not int
        or static_target["source_size_bytes"] < 1
        or authorities
        != {
            "auto_submit_authorized": False,
            "exploit_effect_proven": True,
            "exploit_proven": True,
            "flag_proven": False,
            "primitive_proven": True,
            "proof_satisfied": False,
            "stage_advance_authorized": False,
        }
        or type(effect["child_experiment_id"]) is not str
        or not effect["child_experiment_id"]
        or type(evidence["crash_clean_proofs"]) is not int
        or evidence["crash_clean_proofs"] != 6
        or type(evidence["effect_clean_proofs"]) is not int
        or evidence["effect_clean_proofs"] != 6
        or type(evidence["ip_control_clean_proofs"]) is not int
        or evidence["ip_control_clean_proofs"] != 3
        or type(evidence["runtime_snapshot_clean_proofs"]) is not int
        or evidence["runtime_snapshot_clean_proofs"] != 1
        or type(evidence["network_none"]) is not int
        or evidence["network_none"] != 16
        or evidence["sandbox"] != "production_real_docker"
        or type(evidence["total_real_clean_proofs"]) is not int
        or evidence["total_real_clean_proofs"] != len(records)
        or fixture["baseline_target"] != "0x0000500012345678"
        or type(fixture["controlled_offset"]) is not int
        or fixture["controlled_offset"] != 17
        or type(fixture["controlled_width_bytes"]) is not int
        or fixture["controlled_width_bytes"] != 8
        or type(fixture["emit_sentinel_address"]) is not str
        or re.fullmatch(
            r"0x[0-9a-f]{16}",
            fixture["emit_sentinel_address"],
        )
        is None
        or type(result["setup_boundary"]) is not str
        or not result["setup_boundary"]
    ):
        raise RuntimeError(
            f"Pwn dependency repetition {index} did not meet release gate"
        )
    return result


def _validate_repetition_freshness(
    results: list[dict[str, object]],
) -> None:
    if type(results) is not list or len(results) != REPETITIONS:
        raise AssertionError(
            "Pwn dependency repetition cohort is incomplete"
        )
    graph_ids = [
        result["dependency"]["graph_id"] for result in results
    ]
    child_ids = [
        result["effect"]["child_experiment_id"]
        for result in results
    ]
    physical_manifests = [
        result["evidence_execution"]["physical_manifest_sha256"]
        for result in results
    ]
    run_ids = [
        record["run_id"]
        for result in results
        for record in result["evidence_execution"]["physical_records"]
    ]
    sentinel_hashes = [
        record["sentinel_sha256"]
        for result in results
        for record in result["effect"]["records"]
    ]
    if (
        len(set(graph_ids)) != REPETITIONS
        or len(set(child_ids)) != REPETITIONS
        or len(set(physical_manifests)) != REPETITIONS
        or len(run_ids) != 16 * REPETITIONS
        or len(set(run_ids)) != len(run_ids)
        or len(sentinel_hashes) != 6 * REPETITIONS
        or len(set(sentinel_hashes)) != len(sentinel_hashes)
    ):
        raise AssertionError(
            "fresh Pwn dependency repetitions reused physical evidence"
        )


def _one(index: int, digest: str) -> dict[str, object]:
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(REPOSITORY)
        if not existing_pythonpath
        else str(REPOSITORY) + os.pathsep + existing_pythonpath
    )
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout,
        tempfile.TemporaryFile(mode="w+b") as stderr,
    ):
        completed = subprocess.run(
            (
                sys.executable,
                str(SINGLE_PROOF),
                "--image-digest",
                digest,
            ),
            cwd=REPOSITORY,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            check=False,
            env=environment,
            timeout=900,
        )
        stdout_payload = _read_capture(
            stdout,
            maximum_bytes=MAX_CHILD_STDOUT_BYTES,
            label=f"Pwn dependency repetition {index} stdout",
        )
        stderr_payload = _read_capture(
            stderr,
            maximum_bytes=MAX_CHILD_STDERR_BYTES,
            label=f"Pwn dependency repetition {index} stderr",
        )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Pwn dependency repetition {index} failed: "
            + stderr_payload[-8192:].decode(
                "utf-8",
                errors="replace",
            )
        )
    try:
        decoded = strict_json_loads(
            stdout_payload,
            max_bytes=MAX_CHILD_STDOUT_BYTES,
            max_depth=64,
        )
    except (StrictJSONError, UnicodeError, ValueError) as error:
        raise RuntimeError(
            f"Pwn dependency repetition {index} summary is invalid"
        ) from error
    return _validate_child_summary(
        decoded,
        digest=digest,
        index=index,
    )


def main() -> int:
    digest = _parse_args().image_digest
    if digest != RELEASE_IMAGE_DIGEST:
        raise AssertionError(
            "Pwn dependency release proof refuses a different image digest"
        )
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=REPETITIONS,
        thread_name_prefix="pwn-dependency-release",
    ) as executor:
        futures = [
            executor.submit(_one, index, digest)
            for index in range(1, REPETITIONS + 1)
        ]
        results = [future.result() for future in futures]
    _validate_repetition_freshness(results)
    graph_ids = [
        result["dependency"]["graph_id"]
        for result in results
    ]
    networks = {result["network"] for result in results}
    if networks != {"none"}:
        raise AssertionError(
            "fresh Pwn dependency repetitions changed network policy"
        )
    print(
        json.dumps(
            {
                "candidate_count": sum(
                    result["candidates"] for result in results
                ),
                "graph_ids": graph_ids,
                "image_digest": digest,
                "network": next(iter(networks)),
                "no_leak_required_chains": sum(
                    result["dependency"]["branch"]
                    == "DEPENDENCY_SCOPED_NOT_APPLICABLE"
                    for result in results
                ),
                "ok": all(result["ok"] is True for result in results),
                "real_clean_proofs": sum(
                    result["evidence_execution"][
                        "total_real_clean_proofs"
                    ]
                    for result in results
                ),
                "repetitions": len(results),
                "submission_count": sum(
                    result["submissions"] for result in results
                ),
                "tamper_controls_rejected": sum(
                    1
                    for result in results
                    if result["dependency"][
                        "tamper_control_rejected"
                    ]
                ),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
