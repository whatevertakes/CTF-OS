#!/usr/bin/env python3
"""Run three independent real-Docker Pwn D/V/N/A/P/E release proofs."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from pathlib import Path


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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Require three fresh 16-clean-proof Pwn dependency chains and "
            "three rehashed tamper-control rejections."
        )
    )
    parser.add_argument("--image-digest", required=True)
    return parser.parse_args()


def _one(index: int, digest: str) -> dict[str, object]:
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(REPOSITORY)
        if not existing_pythonpath
        else str(REPOSITORY) + os.pathsep + existing_pythonpath
    )
    completed = subprocess.run(
        (
            sys.executable,
            str(SINGLE_PROOF),
            "--image-digest",
            digest,
        ),
        cwd=REPOSITORY,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env=environment,
        text=True,
        timeout=900,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Pwn dependency repetition {index} failed: "
            + completed.stderr[-8192:]
        )
    lines = [
        line
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    if not lines:
        raise RuntimeError(
            f"Pwn dependency repetition {index} returned no summary"
        )
    try:
        result = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Pwn dependency repetition {index} summary is invalid"
        ) from error
    dependency = result.get("dependency")
    evidence = result.get("evidence_execution")
    if (
        result.get("ok") is not True
        or result.get("image_digest") != digest
        or result.get("network") != "none"
        or result.get("candidates") != 0
        or result.get("submissions") != 0
        or type(dependency) is not dict
        or dependency.get("branch")
        != "DEPENDENCY_SCOPED_NOT_APPLICABLE"
        or dependency.get("gate_route")
        != ["D", "V", "N/A", "P", "E"]
        or dependency.get("primitive_recomputed") is not True
        or dependency.get("tamper_control_rejected") is not True
        or type(evidence) is not dict
        or evidence.get("total_real_clean_proofs") != 16
        or evidence.get("sandbox") != "production_real_docker"
    ):
        raise RuntimeError(
            f"Pwn dependency repetition {index} did not meet release gate"
        )
    return result


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
    graph_ids = [
        result["dependency"]["graph_id"]
        for result in results
    ]
    if len(set(graph_ids)) != REPETITIONS:
        raise AssertionError(
            "fresh Pwn dependency repetitions reused a graph identity"
        )
    print(
        json.dumps(
            {
                "candidate_count": sum(
                    result["candidates"] for result in results
                ),
                "graph_ids": graph_ids,
                "image_digest": digest,
                "network": "none",
                "no_leak_required_chains": REPETITIONS,
                "ok": True,
                "real_clean_proofs": 16 * REPETITIONS,
                "repetitions": REPETITIONS,
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
