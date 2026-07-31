#!/usr/bin/env python3
"""Run the exact local Docker release gates for every CTF category.

This is a developer release validator, not a product scheduler.  Its command
set is closed in source, every child receives the same exact image ID, and no
challenge name, model configuration, remote target, or submission authority
can be supplied on the command line.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO, Sequence


REPOSITORY = Path(__file__).resolve().parent.parent
PROTOCOL = "ctfos.all_category_release_matrix.v1"
SCHEMA_VERSION = 1
IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
PWN_INTERACTION_PRODUCER_SHA256 = (
    "d2a5a4370242adb0fae75ac4ddc68ffd"
    "43952e671ba0abc0ad68f1924423b5b9"
)
CAPTURE_LIMIT_BYTES = 1_048_576
SUMMARY_LINE_LIMIT_BYTES = 65_536
REPORT_LIMIT_BYTES = 131_072
DEFAULT_TIMEOUT_SECONDS = 1_800
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 3_600
DEFAULT_JOBS = 2
MAX_JOBS = 3
TRUNCATION_MARKER = (
    b"\n... [ctfos release matrix omitted bounded middle bytes] ...\n"
)
SAFE_CHILD_ENVIRONMENT_KEYS = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NO_COLOR",
        "PATH",
        "TZ",
    }
)


@dataclasses.dataclass(frozen=True)
class ReleaseTask:
    id: str
    categories: tuple[str, ...]
    script: str
    network_contract: str


# Closed command inventory.  Adding a gate is a reviewed source change; users
# cannot inject commands or select challenges through this runner.
RELEASE_TASKS = (
    ReleaseTask(
        id="pwn_dependency_effect",
        categories=("pwn",),
        script="scripts/check-pwn-dependency-hotpath-docker.py",
        network_contract="none",
    ),
    ReleaseTask(
        id="pwn_interaction_effect",
        categories=("pwn",),
        script="scripts/check-pwn-interaction-hotpath-docker.py",
        network_contract="none",
    ),
    ReleaseTask(
        id="web_state_impact",
        categories=("web",),
        script="scripts/check-web-impact-docker-hotpath.py",
        network_contract="docker_internal_local_targets",
    ),
    ReleaseTask(
        id="web_active_probe",
        categories=("web",),
        script="scripts/check-web-active-probe-docker-hotpath.py",
        network_contract="docker_internal_local_targets",
    ),
    ReleaseTask(
        id="rev_original_binary_acceptance",
        categories=("rev",),
        script=(
            "scripts/"
            "check-managed-rev-accepted-input-hotpath-docker.py"
        ),
        network_contract="none",
    ),
    ReleaseTask(
        id="crypto_metamorphic_and_misc_transform",
        categories=("crypto", "misc"),
        script="scripts/check-crypto-misc-docker-hotpaths.py",
        network_contract="none",
    ),
    ReleaseTask(
        id="forensic_assertion_graph",
        categories=("forensics",),
        script="scripts/check-forensic-assertion-hotpath-docker.py",
        network_contract="none",
    ),
)


class ReleaseMatrixError(RuntimeError):
    """A fail-closed release validation error."""


def _canonical_json(value: object) -> bytes:
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


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _command_contract() -> dict[str, object]:
    return {
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "tasks": [
            {
                "categories": list(task.categories),
                "id": task.id,
                "network_contract": task.network_contract,
                "script": task.script,
            }
            for task in RELEASE_TASKS
        ],
    }


def _git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if check and completed.returncode != 0:
        raise ReleaseMatrixError(
            "git preflight failed: "
            + completed.stderr.strip()[:2_048]
        )
    return completed


def _tracked_script_sha256(relative: str) -> str:
    path = REPOSITORY / relative
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ReleaseMatrixError(
            f"release script is missing: {relative}"
        ) from error
    if REPOSITORY not in resolved.parents:
        raise ReleaseMatrixError(
            f"release script escapes the repository: {relative}"
        )
    if path.is_symlink() or not path.is_file():
        raise ReleaseMatrixError(
            f"release script must be a regular non-symlink file: {relative}"
        )
    _git("ls-files", "--error-unmatch", "--", relative)
    head_blob = _git("show", f"HEAD:{relative}").stdout.encode("utf-8")
    working = path.read_bytes()
    if working != head_blob:
        raise ReleaseMatrixError(
            f"release script differs from HEAD: {relative}"
        )
    return _sha256(working)


def _source_snapshot() -> dict[str, object]:
    top = Path(
        _git("rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if top != REPOSITORY:
        raise ReleaseMatrixError("release runner is not at its repository root")
    commit = _git("rev-parse", "HEAD").stdout.strip()
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseMatrixError("HEAD is not an exact Git commit")
    status = _git(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout
    if status:
        lines = status.splitlines()
        raise ReleaseMatrixError(
            "release matrix requires a clean source tree; first entry: "
            + lines[0][:512]
        )
    runner_relative = str(Path(__file__).resolve().relative_to(REPOSITORY))
    script_hashes = {
        relative: _tracked_script_sha256(relative)
        for relative in (
            runner_relative,
            *(task.script for task in RELEASE_TASKS),
        )
    }
    return {
        "clean": True,
        "commit": commit,
        "scripts": script_hashes,
    }


def _inspect_image(image_digest: str) -> dict[str, str]:
    if IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None:
        raise ReleaseMatrixError(
            "image digest must be sha256 plus 64 lowercase hexadecimal digits"
        )
    completed = subprocess.run(
        (
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image_digest,
        ),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise ReleaseMatrixError(
            "exact release image is unavailable: "
            + completed.stderr.strip()[:2_048]
        )
    inspected = completed.stdout.strip()
    if inspected != image_digest:
        raise ReleaseMatrixError(
            "Docker inspection did not resolve to the requested exact image ID"
        )
    return {"digest": image_digest, "inspected_id": inspected}


class _BoundedCapture:
    def __init__(self, *, limit_bytes: int = CAPTURE_LIMIT_BYTES) -> None:
        if limit_bytes <= len(TRUNCATION_MARKER) + 2:
            raise ValueError("capture limit is too small")
        usable = limit_bytes - len(TRUNCATION_MARKER)
        self.prefix_limit = usable // 2
        self.tail_limit = usable - self.prefix_limit
        self.limit_bytes = limit_bytes
        self.prefix = bytearray()
        self.tail = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.error: BaseException | None = None

    def consume(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                self.digest.update(chunk)
                needed = self.prefix_limit - len(self.prefix)
                if needed > 0:
                    self.prefix.extend(chunk[:needed])
                    chunk = chunk[needed:]
                if chunk:
                    self.tail.extend(chunk)
                    if len(self.tail) > self.tail_limit:
                        del self.tail[: len(self.tail) - self.tail_limit]
        except BaseException as error:
            self.error = error
        finally:
            stream.close()

    @property
    def truncated(self) -> bool:
        return self.total_bytes > len(self.prefix) + len(self.tail)

    def payload(self) -> bytes:
        if self.truncated:
            value = bytes(self.prefix) + TRUNCATION_MARKER + bytes(self.tail)
        else:
            value = bytes(self.prefix) + bytes(self.tail)
        if len(value) > self.limit_bytes:
            raise ReleaseMatrixError("bounded stream capture exceeded its limit")
        return value

    def metadata(self, locator: str) -> dict[str, object]:
        return {
            "captured_bytes": len(self.payload()),
            "locator": locator,
            "sha256": "sha256:" + self.digest.hexdigest(),
            "stream_bytes": self.total_bytes,
            "truncated": self.truncated,
        }


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in SAFE_CHILD_ENVIRONMENT_KEYS
    }
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(REPOSITORY)
        if not existing
        else str(REPOSITORY) + os.pathsep + existing
    )
    environment["CTFOS_RELEASE_MATRIX"] = "1"
    return environment


def _exact_mapping(
    value: object,
    *,
    required: frozenset[str],
    label: str,
    allow_extra: bool = False,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ReleaseMatrixError(f"{label} is not an object")
    keys = set(value)
    if not required.issubset(keys) or (
        not allow_extra and keys != required
    ):
        raise ReleaseMatrixError(f"{label} schema is invalid")
    return value


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) is not None
    )


def _validate_pwn_summary(value: dict[str, object]) -> None:
    required = frozenset(
        {
            "candidate_count",
            "graph_ids",
            "image_digest",
            "network",
            "no_leak_required_chains",
            "ok",
            "real_clean_proofs",
            "repetitions",
            "submission_count",
            "tamper_controls_rejected",
        }
    )
    root = _exact_mapping(
        value,
        required=required,
        label="pwn release summary",
    )
    graph_ids = root["graph_ids"]
    if (
        root["ok"] is not True
        or root["network"] != "none"
        or root["candidate_count"] != 0
        or root["submission_count"] != 0
        or root["repetitions"] != 3
        or root["no_leak_required_chains"] != 3
        or root["real_clean_proofs"] != 48
        or root["tamper_controls_rejected"] != 3
        or type(graph_ids) is not list
        or len(graph_ids) != 3
        or len(set(graph_ids)) != 3
        or any(type(item) is not str or not item for item in graph_ids)
    ):
        raise ReleaseMatrixError(
            "pwn dependency summary did not meet its exact oracle"
        )


def _validate_pwn_interaction_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset(
            {
                "authority",
                "bindings",
                "evaluation",
                "failure_control",
                "image_digest",
                "network",
                "ok",
                "parent",
                "preissue",
                "protocol",
                "sandbox",
                "source_challenge",
                "transport",
            }
        ),
        label="pwn interaction release summary",
    )
    source = _exact_mapping(
        root["source_challenge"],
        required=frozenset(
            {
                "category",
                "challenge_id",
                "contest_id",
                "source_sha256",
            }
        ),
        label="pwn interaction source summary",
    )
    bindings = _exact_mapping(
        root["bindings"],
        required=frozenset(
            {
                "image_digest",
                "preissue_sha256",
                "producer_sha256",
                "recipe_sha256",
                "source_sha256",
            }
        ),
        label="pwn interaction immutable bindings",
    )
    parent = _exact_mapping(
        root["parent"],
        required=frozenset(
            {"authority", "experiment_id", "fact_id", "run_id"}
        ),
        label="pwn interaction parent summary",
    )
    preissue = _exact_mapping(
        root["preissue"],
        required=frozenset(
            {
                "preissued_before_first_run",
                "replay_count",
                "sha256",
                "status",
                "terminal",
            }
        ),
        label="pwn interaction preissue summary",
    )
    evaluation = _exact_mapping(
        root["evaluation"],
        required=frozenset(
            {
                "attack_replays",
                "control_replays",
                "matched_terminal",
                "passed",
                "reason_code",
                "sha256",
                "unique_sentinels",
            }
        ),
        label="pwn interaction evaluation summary",
    )
    transport = _exact_mapping(
        root["transport"],
        required=frozenset(
            {
                "canonical_scope_fingerprint",
                "fresh_clean_workspaces",
                "network_none",
                "one_shot",
                "physical_identities",
                "proof_outputs_per_run",
                "unique_clean_prefix_count",
                "unique_proof_identity_count",
            }
        ),
        label="pwn interaction transport summary",
    )
    authority = _exact_mapping(
        root["authority"],
        required=frozenset(
            {
                "auto_submit_authorized",
                "candidates_added",
                "executed_fact_added",
                "progress_added",
                "status_changed",
                "submissions_added",
            }
        ),
        label="pwn interaction authority summary",
    )
    failure = _exact_mapping(
        root["failure_control"],
        required=frozenset(
            {
                "candidates_added",
                "facts_added",
                "failure_mode",
                "progress_added",
                "receipts",
                "runs_terminal",
                "state_store_reopen_ok",
                "status",
                "submissions_added",
                "terminal",
                "tested",
            }
        ),
        label="pwn interaction failure control",
    )
    physical_identities = transport["physical_identities"]
    physical_tuples: list[tuple[str, str, str]] = []
    clean_prefixes: list[str] = []
    canonical_scope = transport["canonical_scope_fingerprint"]
    if type(physical_identities) is list:
        for ordinal, item in enumerate(physical_identities, start=1):
            identity_record = _exact_mapping(
                item,
                required=frozenset(
                    {
                        "clean_prefix",
                        "sandbox_run_id",
                        "scope_fingerprint",
                    }
                ),
                label=(
                    "pwn interaction physical identity "
                    f"{ordinal}"
                ),
            )
            scope = identity_record["scope_fingerprint"]
            sandbox_run_id = identity_record["sandbox_run_id"]
            clean_prefix = identity_record["clean_prefix"]
            if (
                not _valid_sha256(scope)
                or scope != canonical_scope
                or type(sandbox_run_id) is not str
                or not sandbox_run_id
                or type(clean_prefix) is not str
                or re.fullmatch(r"clean-[0-9a-f]{12}", clean_prefix)
                is None
            ):
                raise ReleaseMatrixError(
                    "pwn interaction physical identity is invalid"
                )
            physical_tuples.append(
                (str(scope), sandbox_run_id, clean_prefix)
            )
            clean_prefixes.append(clean_prefix)
    parent_authority = parent["authority"]
    parent_pointer_valid = (
        type(parent["experiment_id"]) is str
        and bool(parent["experiment_id"])
        and (
            (
                parent_authority == "canonical_executed_parent_v1"
                and type(parent["run_id"]) is str
                and bool(parent["run_id"])
                and type(parent["fact_id"]) is str
                and bool(parent["fact_id"])
            )
            or (
                parent_authority == "typed_pwn_ip_control_v1"
                and parent["run_id"] is None
                and parent["fact_id"] is None
            )
        )
    )
    if (
        root["ok"] is not True
        or root["protocol"] != "ctfos.pwn.interaction.hotpath.v1"
        or root["network"] != "none"
        or root["sandbox"] != "production_real_docker"
        or bindings["image_digest"] != root["image_digest"]
        or bindings["producer_sha256"]
        != PWN_INTERACTION_PRODUCER_SHA256
        or not _valid_sha256(bindings["source_sha256"])
        or not _valid_sha256(bindings["recipe_sha256"])
        or not _valid_sha256(bindings["preissue_sha256"])
        or bindings["source_sha256"] != source["source_sha256"]
        or bindings["preissue_sha256"] != preissue["sha256"]
        or source["category"] != "pwn"
        or type(source["contest_id"]) is not str
        or not source["contest_id"]
        or type(source["challenge_id"]) is not str
        or not source["challenge_id"]
        or not _valid_sha256(source["source_sha256"])
        or not parent_pointer_valid
        or not _valid_sha256(preissue["sha256"])
        or preissue["status"] != "passed"
        or preissue["terminal"] is not True
        or preissue["replay_count"] != 6
        or preissue["preissued_before_first_run"] is not True
        or evaluation["passed"] is not True
        or evaluation["reason_code"]
        != "validated_three_positive_three_control_replays"
        or not _valid_sha256(evaluation["sha256"])
        or evaluation["attack_replays"] != 3
        or evaluation["control_replays"] != 3
        or evaluation["unique_sentinels"] != 6
        or evaluation["matched_terminal"] is not True
        or not _valid_sha256(canonical_scope)
        or transport["fresh_clean_workspaces"] != 6
        or len(physical_tuples) != 6
        or len(set(physical_tuples)) != 6
        or len(set(clean_prefixes)) != 6
        or transport["unique_clean_prefix_count"] != 6
        or transport["unique_proof_identity_count"] != 6
        or transport["network_none"] != 6
        or transport["one_shot"] != 6
        or transport["proof_outputs_per_run"] != 4
        or authority["executed_fact_added"] != 1
        or authority["progress_added"] != 1
        or authority["candidates_added"] != 0
        or authority["submissions_added"] != 0
        or authority["status_changed"] is not False
        or authority["auto_submit_authorized"] is not False
        or failure["tested"] is not True
        or failure["failure_mode"] != "preissue_sha256_tamper"
        or failure["status"] != "failed"
        or failure["terminal"] is not True
        or failure["state_store_reopen_ok"] is not True
        or failure["runs_terminal"] != 6
        or failure["receipts"] != 6
        or failure["facts_added"] != 0
        or failure["progress_added"] != 0
        or failure["candidates_added"] != 0
        or failure["submissions_added"] != 0
    ):
        raise ReleaseMatrixError(
            "pwn interaction summary did not meet its exact 3+3 oracle"
        )


def _validate_web_impact_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset(
            {
                "control_target",
                "engine",
                "image_digest",
                "network",
                "ok",
                "vulnerable_target",
            }
        ),
        label="web impact release summary",
    )
    engine = _exact_mapping(
        root["engine"],
        required=frozenset(
            {
                "automatic_submissions",
                "canonical_requests_preissued",
                "executed_facts",
                "network_enforcement",
                "physical_artifacts_revalidated",
                "physical_run_sidecars_revalidated",
                "physical_transport_receipts_revalidated",
                "progress_markers",
                "replays",
                "runtime_request_response_differential_confirmed",
                "source_sink_observed",
                "state_revision",
                "verdict",
            }
        ),
        label="web impact engine summary",
        # New semantic-authority fields may be added without weakening the
        # required physical transport oracle below.
        allow_extra=True,
    )
    network = _exact_mapping(
        root["network"],
        required=frozenset({"external_internet", "internal", "name"}),
        label="web impact network summary",
    )
    vulnerable = _exact_mapping(
        root["vulnerable_target"],
        required=frozenset(
            {"accepted_requests", "endpoint_counts", "extract_status"}
        ),
        label="web vulnerable target summary",
    )
    control = _exact_mapping(
        root["control_target"],
        required=frozenset(
            {"accepted_requests", "endpoint_counts", "extract_status"}
        ),
        label="web control target summary",
    )
    vulnerable_counts = vulnerable["endpoint_counts"]
    control_counts = control["endpoint_counts"]
    if (
        root["ok"] is not True
        or network["external_internet"] is not False
        or network["internal"] is not True
        or type(network["name"]) is not str
        or not network["name"]
        or engine["automatic_submissions"] != 0
        or engine["canonical_requests_preissued"] != 6
        or engine["executed_facts"] != 1
        or engine["network_enforcement"] != "proxy"
        or engine["physical_artifacts_revalidated"] != 88
        or engine["physical_run_sidecars_revalidated"] != 18
        or engine["physical_transport_receipts_revalidated"] != 6
        or engine["progress_markers"] != 1
        or engine["replays"] != 6
        or engine[
            "runtime_request_response_differential_confirmed"
        ]
        is not True
        or engine["source_sink_observed"] is not False
        or engine["verdict"] != "CONFIRMED"
        or vulnerable["accepted_requests"] != 18
        or vulnerable["extract_status"] != 200
        or control["accepted_requests"] != 18
        or control["extract_status"] != 403
        or type(vulnerable_counts) is not dict
        or type(control_counts) is not dict
        or vulnerable_counts != control_counts
        or len(vulnerable_counts) != 6
        or set(vulnerable_counts.values()) != {3}
    ):
        raise ReleaseMatrixError(
            "web impact summary did not meet its exact differential oracle"
        )


def _validate_rev_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset(
            {
                "candidates",
                "cleaned_containers",
                "fact_count",
                "image_digest",
                "managed_action",
                "network",
                "ok",
                "progress_count",
                "receipts",
                "runs",
                "submissions",
            }
        ),
        label="rev release summary",
    )
    if (
        root["ok"] is not True
        or root["managed_action"] != "rev_accepted_input"
        or root["network"] != "none"
        or root["runs"] != 6
        or root["receipts"] != 6
        or root["fact_count"] != 1
        or root["progress_count"] != 1
        or root["candidates"] != 0
        or root["submissions"] != 0
        or type(root["cleaned_containers"]) is not int
        or not 0 <= root["cleaned_containers"] <= 6
    ):
        raise ReleaseMatrixError(
            "rev acceptance summary did not meet its exact 3+3 oracle"
        )


def _validate_crypto_runtime(
    value: object,
    *,
    runtime: str,
) -> None:
    record = _exact_mapping(
        value,
        required=frozenset(
            {
                "candidate_status",
                "network",
                "one_shot_consumed",
                "oracle_authority",
                "oracle_preissue_status",
                "runtime",
                "runs",
                "successful_attempts",
                "submissions",
            }
        ),
        label=f"crypto {runtime} summary",
    )
    if (
        record["candidate_status"] != "READY_TO_SUBMIT"
        or record["network"] != "none"
        or record["one_shot_consumed"] is not True
        or record["oracle_authority"] != "managed_oracle_preissue_v1"
        or record["oracle_preissue_status"] != "consumed"
        or record["runtime"] != runtime
        or record["runs"] != 6
        or record["successful_attempts"] != 6
        or record["submissions"] != 0
    ):
        raise ReleaseMatrixError(
            f"crypto {runtime} summary did not meet its exact 3+3 oracle"
        )


def _validate_crypto_misc_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset({"crypto", "image_digest", "misc", "ok"}),
        label="crypto/misc release summary",
    )
    crypto = _exact_mapping(
        root["crypto"],
        required=frozenset({"python", "sage"}),
        label="crypto release summary",
    )
    _validate_crypto_runtime(crypto["python"], runtime="python")
    _validate_crypto_runtime(crypto["sage"], runtime="sage")
    misc = _exact_mapping(
        root["misc"],
        required=frozenset(
            {
                "candidate_status",
                "candidate_only",
                "network",
                "one_shot_consumed",
                "oracle_authority",
                "oracle_control_runs",
                "oracle_preissue_status",
                "runs",
                "submissions",
                "transform_evidence_passed",
                "transform_runs",
                "verification_runs",
            }
        ),
        label="misc release summary",
    )
    if (
        root["ok"] is not True
        or misc["candidate_status"] != "OBSERVED_CANDIDATE"
        or misc["candidate_only"] is not True
        or misc["network"] != "none"
        or misc["one_shot_consumed"] is not True
        or misc["oracle_authority"] != "managed_oracle_preissue_v1"
        or misc["oracle_control_runs"] != 1
        or misc["oracle_preissue_status"] != "consumed"
        or misc["runs"] != 5
        or misc["submissions"] != 0
        or misc["transform_evidence_passed"] is not True
        or misc["transform_runs"] != 1
        or misc["verification_runs"] != 3
    ):
        raise ReleaseMatrixError(
            "misc summary did not meet its exact DAG+3 oracle"
        )


def _validate_forensic_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset(
            {
                "assertion_facts",
                "assertion_progress",
                "candidates",
                "cleanup",
                "confirmed",
                "control",
                "image_digest",
                "index_execution_sha256",
                "network",
                "ok",
                "operator_plans",
                "pointer",
                "readiness_probes",
                "sandbox",
                "state_status",
                "submissions",
            }
        ),
        label="forensic release summary",
    )
    control = _exact_mapping(
        root["control"],
        required=frozenset({"algorithms", "confirmed", "reason_codes"}),
        label="forensic control summary",
    )
    plans = _exact_mapping(
        root["operator_plans"],
        required=frozenset({"control", "positive"}),
        label="forensic operator plans",
    )
    pointer = _exact_mapping(
        root["pointer"],
        required=frozenset(
            {
                "kind",
                "length_bytes",
                "offset_bytes",
                "pointer_id",
                "source_path",
                "source_sha256",
                "sha256",
            }
        ),
        label="forensic evidence pointer",
        allow_extra=True,
    )
    confirmed = root["confirmed"]
    confirmations_valid = (
        type(confirmed) is list
        and len(confirmed) == 3
        and [item.get("ordinal") for item in confirmed if type(item) is dict]
        == [1, 2, 3]
        and all(
            type(item) is dict
            and item.get("algorithms") == ["descriptor", "mmap"]
            and item.get("record_count") == 2
            and _valid_sha256(item.get("evaluation_sha256"))
            for item in confirmed
        )
    )
    if (
        root["ok"] is not True
        or root["assertion_facts"] != 3
        or root["assertion_progress"] != 3
        or root["candidates"] != 0
        or root["submissions"] != 0
        or not confirmations_valid
        or root["readiness_probes"] != 4
        or root["network"] != "none"
        or root["sandbox"] != "production_real_docker"
        or root["cleanup"] != "verified"
        or control["algorithms"] != ["descriptor", "mmap"]
        or control["confirmed"] is not False
        or type(control["reason_codes"]) is not list
        or not control["reason_codes"]
        or not any(
            "observation_request_binding_mismatch" in item
            for item in control["reason_codes"]
            if type(item) is str
        )
        or not all(_valid_sha256(item) for item in plans.values())
        or not _valid_sha256(root["index_execution_sha256"])
        or pointer["kind"] != "file_range"
        or not _valid_sha256(pointer["source_sha256"])
        or not _valid_sha256(pointer["sha256"])
    ):
        raise ReleaseMatrixError(
            "forensic summary did not meet its exact assertion oracle"
        )


def _validate_web_active_summary(value: dict[str, object]) -> None:
    root = _exact_mapping(
        value,
        required=frozenset(
            {
                "automatic_submission_count",
                "image_digest",
                "network",
                "oob",
                "protocol",
                "race",
                "schema_version",
                "target_audit",
            }
        ),
        label="web active-probe release summary",
    )
    network = _exact_mapping(
        root["network"],
        required=frozenset(
            {
                "external_internet",
                "internal",
                "name",
            }
        ),
        label="web active-probe network summary",
    )
    mode_required = frozenset(
        {
            "attempt_id",
            "candidate_count",
            "evaluation_sha256",
            "executed_fact_count",
            "graph_sha256",
            "mode",
            "physical_artifact_count",
            "replay_count",
            "submission_count",
        }
    )
    race = _exact_mapping(
        root["race"],
        required=mode_required,
        label="web active-probe race summary",
    )
    oob = _exact_mapping(
        root["oob"],
        required=mode_required,
        label="web active-probe OOB summary",
    )
    target_audit = _exact_mapping(
        root["target_audit"],
        required=frozenset(
            {
                "control_oob_callbacks",
                "control_race_requests",
                "maximum_parallel_race_requests",
                "vulnerable_oob_callbacks",
                "vulnerable_race_requests",
            }
        ),
        label="web active-probe target audit",
    )
    if (
        root["protocol"]
        != "ctfos.web.active_probe.docker_release.v1"
        or root["schema_version"] != 1
        or root["automatic_submission_count"] != 0
        or network["external_internet"] is not False
        or network["internal"] is not True
        or type(network["name"]) is not str
        or not network["name"].startswith("ctfos-web-active-")
        or type(race["attempt_id"]) is not str
        or re.fullmatch(
            r"web-active-[0-9a-f]{32}",
            race["attempt_id"],
        )
        is None
        or type(oob["attempt_id"]) is not str
        or re.fullmatch(
            r"web-active-[0-9a-f]{32}",
            oob["attempt_id"],
        )
        is None
        or race["attempt_id"] == oob["attempt_id"]
        or race["mode"] != "race"
        or oob["mode"] != "oob"
        or race["replay_count"] != 6
        or oob["replay_count"] != 6
        or race["executed_fact_count"] != 1
        or oob["executed_fact_count"] != 1
        or race["candidate_count"] != 0
        or oob["candidate_count"] != 0
        or race["submission_count"] != 0
        or oob["submission_count"] != 0
        or race["physical_artifact_count"] != 29
        or oob["physical_artifact_count"] != 26
        or not _valid_sha256(race["evaluation_sha256"])
        or not _valid_sha256(oob["evaluation_sha256"])
        or not _valid_sha256(race["graph_sha256"])
        or not _valid_sha256(oob["graph_sha256"])
        or target_audit
        != {
            "control_oob_callbacks": 0,
            "control_race_requests": 6,
            "maximum_parallel_race_requests": 2,
            "vulnerable_oob_callbacks": 3,
            "vulnerable_race_requests": 6,
        }
    ):
        raise ReleaseMatrixError(
            "web_active_probe did not meet its exact race/OOB oracle"
        )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=10)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=10)


def _last_nonempty_line(payload: bytes) -> bytes:
    for line in reversed(payload.splitlines()):
        if line.strip():
            return line
    return b""


def _validate_child_summary(
    task: ReleaseTask,
    capture: _BoundedCapture,
    image_digest: str,
) -> str:
    last_line = _last_nonempty_line(
        bytes(capture.tail) if capture.truncated else capture.payload()
    )
    if not last_line:
        raise ReleaseMatrixError(f"{task.id} emitted no JSON summary")
    if len(last_line) > SUMMARY_LINE_LIMIT_BYTES:
        raise ReleaseMatrixError(f"{task.id} JSON summary is oversized")
    try:
        value = json.loads(last_line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseMatrixError(
            f"{task.id} final nonempty stdout line is not JSON"
        ) from error
    if type(value) is not dict:
        raise ReleaseMatrixError(f"{task.id} JSON summary is not an object")
    if value.get("image_digest") != image_digest:
        raise ReleaseMatrixError(
            f"{task.id} did not bind the exact release image digest"
        )
    validators = {
        "pwn_dependency_effect": _validate_pwn_summary,
        "pwn_interaction_effect": _validate_pwn_interaction_summary,
        "web_state_impact": _validate_web_impact_summary,
        "web_active_probe": _validate_web_active_summary,
        "rev_original_binary_acceptance": _validate_rev_summary,
        "crypto_metamorphic_and_misc_transform": (
            _validate_crypto_misc_summary
        ),
        "forensic_assertion_graph": _validate_forensic_summary,
    }
    validator = validators.get(task.id)
    if validator is None:
        raise ReleaseMatrixError(
            f"{task.id} has no field-level release oracle"
        )
    validator(value)
    return _sha256(_canonical_json(value))


def _write_capture(path: Path, capture: _BoundedCapture) -> None:
    path.write_bytes(capture.payload())
    path.chmod(0o600)


def _run_task(
    task: ReleaseTask,
    *,
    image_digest: str,
    artifact_root: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    command = (
        sys.executable,
        str(REPOSITORY / task.script),
        "--image-digest",
        image_digest,
    )
    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    started = time.monotonic_ns()
    timed_out = False
    process = subprocess.Popen(
        command,
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_child_environment(),
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    readers = (
        threading.Thread(
            target=stdout_capture.consume,
            args=(process.stdout,),
            daemon=True,
            name=f"{task.id}-stdout",
        ),
        threading.Thread(
            target=stderr_capture.consume,
            args=(process.stderr,),
            daemon=True,
            name=f"{task.id}-stderr",
        ),
    )
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
    for reader in readers:
        reader.join(timeout=30)
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    if any(reader.is_alive() for reader in readers):
        raise ReleaseMatrixError(f"{task.id} output reader did not terminate")
    for capture in (stdout_capture, stderr_capture):
        if capture.error is not None:
            raise ReleaseMatrixError(
                f"{task.id} output capture failed"
            ) from capture.error

    stdout_name = f"{task.id}.stdout.log"
    stderr_name = f"{task.id}.stderr.log"
    _write_capture(artifact_root / stdout_name, stdout_capture)
    _write_capture(artifact_root / stderr_name, stderr_capture)
    status = "passed"
    failure_reason: str | None = None
    summary_sha256: str | None = None
    if timed_out:
        status = "failed"
        failure_reason = "timeout"
    elif process.returncode != 0:
        status = "failed"
        failure_reason = f"exit_{process.returncode}"
    else:
        try:
            summary_sha256 = _validate_child_summary(
                task,
                stdout_capture,
                image_digest,
            )
        except ReleaseMatrixError as error:
            status = "failed"
            failure_reason = str(error)
    return {
        "categories": list(task.categories),
        "command": list(command),
        "duration_ms": duration_ms,
        "exit_code": process.returncode,
        "failure_reason": failure_reason,
        "id": task.id,
        "network_contract": task.network_contract,
        "status": status,
        "stderr": stderr_capture.metadata(stderr_name),
        "stdout": stdout_capture.metadata(stdout_name),
        "summary_sha256": summary_sha256,
        "timed_out": timed_out,
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the closed, developer-only exact-Docker release matrix for "
            "Pwn, Web, Rev, Crypto, Forensic, and Misc."
        )
    )
    parser.add_argument(
        "--image-digest",
        required=True,
        help="exact local sha256:<64 lowercase hex> Docker image ID",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=DEFAULT_JOBS,
        choices=range(1, MAX_JOBS + 1),
        metavar=f"1..{MAX_JOBS}",
        help="bounded local gate parallelism (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            f"per-gate timeout in {MIN_TIMEOUT_SECONDS}.."
            f"{MAX_TIMEOUT_SECONDS} seconds"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "new artifact directory; default creates one below "
            ".ctfos/release-matrix/"
        ),
    )
    arguments = parser.parse_args(argv)
    if not (
        MIN_TIMEOUT_SECONDS
        <= arguments.timeout_seconds
        <= MAX_TIMEOUT_SECONDS
    ):
        parser.error(
            f"--timeout-seconds must be in {MIN_TIMEOUT_SECONDS}.."
            f"{MAX_TIMEOUT_SECONDS}"
        )
    return arguments


def _new_artifact_root(requested: Path | None) -> Path:
    if requested is None:
        parent = REPOSITORY / ".ctfos" / "release-matrix"
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return Path(
            tempfile.mkdtemp(
                prefix="run-",
                dir=parent,
            )
        ).resolve()
    path = requested.expanduser().resolve()
    if path.exists():
        raise ReleaseMatrixError(
            "--output-dir must name a new path; existing artifacts are not "
            "overwritten"
        )
    path.mkdir(parents=True, mode=0o700)
    return path


def run_matrix(arguments: argparse.Namespace) -> tuple[Path, dict[str, object]]:
    source_before = _source_snapshot()
    image_before = _inspect_image(arguments.image_digest)
    artifact_root = _new_artifact_root(arguments.output_dir)
    results_by_id: dict[str, dict[str, object]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=arguments.jobs,
        thread_name_prefix="ctfos-release-matrix",
    ) as executor:
        futures = {
            executor.submit(
                _run_task,
                task,
                image_digest=arguments.image_digest,
                artifact_root=artifact_root,
                timeout_seconds=arguments.timeout_seconds,
            ): task
            for task in RELEASE_TASKS
        }
        for future in concurrent.futures.as_completed(futures):
            task = futures[future]
            try:
                results_by_id[task.id] = future.result()
            except BaseException as error:
                results_by_id[task.id] = {
                    "categories": list(task.categories),
                    "command": [
                        sys.executable,
                        str(REPOSITORY / task.script),
                        "--image-digest",
                        arguments.image_digest,
                    ],
                    "duration_ms": 0,
                    "exit_code": None,
                    "failure_reason": (
                        f"runner_error:{type(error).__name__}:{error}"
                    )[:1_024],
                    "id": task.id,
                    "network_contract": task.network_contract,
                    "status": "failed",
                    "stderr": None,
                    "stdout": None,
                    "summary_sha256": None,
                    "timed_out": False,
                }
    stability_error: str | None = None
    try:
        source_after = _source_snapshot()
        image_after = _inspect_image(arguments.image_digest)
        stable = (
            source_after == source_before
            and image_after == image_before
        )
        if not stable:
            stability_error = "source_or_image_changed"
    except ReleaseMatrixError as error:
        stable = False
        stability_error = str(error)[:1_024]
    ordered_results = [
        results_by_id[task.id]
        for task in RELEASE_TASKS
    ]
    covered = sorted(
        {
            category
            for result in ordered_results
            if result["status"] == "passed"
            for category in result["categories"]
        }
    )
    expected = ["crypto", "forensics", "misc", "pwn", "rev", "web"]
    ok = (
        stable
        and covered == expected
        and all(result["status"] == "passed" for result in ordered_results)
    )
    report = {
        "artifact_root": str(artifact_root),
        "categories_passed": covered,
        "command_contract_sha256": _sha256(
            _canonical_json(_command_contract())
        ),
        "image": image_before,
        "ok": ok,
        "policy": {
            "automatic_challenge_selection": False,
            "automatic_challenge_switch": False,
            "automatic_submission": False,
            "capture_limit_bytes_per_stream": CAPTURE_LIMIT_BYTES,
            "jobs": arguments.jobs,
            "model_requests": False,
            "remote_ctf_requests": False,
            "source_and_image_stable": stable,
            "stability_error": stability_error,
            "timeout_seconds_per_task": arguments.timeout_seconds,
        },
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "source": source_before,
        "tasks": ordered_results,
    }
    payload = _canonical_json(report)
    if len(payload) > REPORT_LIMIT_BYTES:
        raise ReleaseMatrixError("release matrix report exceeded its bound")
    report_path = artifact_root / "report.json"
    report_path.write_bytes(payload)
    report_path.chmod(0o600)
    return report_path, report


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_args(argv)
    try:
        report_path, report = run_matrix(arguments)
    except ReleaseMatrixError as error:
        print(f"release matrix refused: {error}", file=sys.stderr)
        return 2
    envelope = {
        "ok": report["ok"],
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
    }
    print(_canonical_json(envelope).decode("ascii"), end="")
    return 0 if report["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
