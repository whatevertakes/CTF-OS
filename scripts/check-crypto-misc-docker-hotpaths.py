#!/usr/bin/env python3
"""Exercise the Crypto and Misc ChallengeEngine hot paths in real Docker.

The release smoke is deliberately self-contained and local.  It opens one
temporary challenge per category, supplies one operator candidate, and invokes
the same public engine methods used by ``ctfos``.  No model API, remote target,
automatic challenge selection, or submission is involved.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from ctf_os.capabilities import inspect_pinned_capabilities
from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.images import validate_image_digest
from ctf_os.models import (
    CandidateStatus,
    ChallengeIdentity,
    FlagCandidate,
)
from ctf_os.schema import STATE_SCHEMA_VERSION


RELEASE_IMAGE_DIGEST = (
    "sha256:"
    "82ef8c155a8bbe9cfe33ce1a475425c77097b6fcefc32b678da1b14bf9c8339a"
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
    (workspace / "variant.json").write_bytes(CRYPTO_VARIANT)
    (workspace / "variant.out").write_bytes(
        CRYPTO_VARIANT_OUTPUT
    )
    _add_candidate(
        engine,
        identity,
        candidate_id=f"C-crypto-docker-{runtime}",
        value=CRYPTO_CANDIDATE,
    )

    final, result = engine.prove_crypto_metamorphic_candidate(
        identity,
        f"C-crypto-docker-{runtime}",
        solver_locator="solver.py",
        original_parameters_locator="original.json",
        variant_parameters_locator="variant.json",
        variant_expected_output_locator="variant.out",
        mutation_id="release-smoke-rsa-parameter-variant",
        runtime=runtime,
    )
    candidate = next(
        item
        for item in final.candidates
        if item.id == f"C-crypto-docker-{runtime}"
    )
    runs = [
        item
        for item in final.runs
        if item.id in candidate.proof_run_ids
    ]
    if (
        result.passed is not True
        or result.required_attempts != 6
        or result.successful_attempts != 6
        or candidate.status is not CandidateStatus.READY_TO_SUBMIT
        or len(runs) != 6
        or any(item.role != "crypto_metamorphic_proof" for item in runs)
        or final.submissions
    ):
        raise AssertionError(
            "Crypto ChallengeEngine Docker hot path did not prove 3+3"
        )
    return {
        "candidate_status": candidate.status.value,
        "network": "none",
        "runtime": runtime,
        "runs": len(runs),
        "successful_attempts": result.successful_attempts,
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
    (workspace / "verify.py").write_text(
        "import pathlib, sys\n"
        f"candidate = {MISC_CANDIDATE.encode('utf-8')!r}\n"
        f"source = {MISC_SOURCE!r}\n"
        "valid = (pathlib.Path(sys.argv[1]).read_bytes() == candidate "
        "and pathlib.Path(sys.argv[2]).read_bytes() == source)\n"
        "raise SystemExit(0 if valid else 42)\n",
        encoding="utf-8",
    )
    (workspace / "misc-spec.json").write_text(
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
                "verifier": {
                    "id": "original-condition",
                    "oracle_id": "release-smoke-oracle-v1",
                    "tool_locator": "verify.py",
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _add_candidate(
        engine,
        identity,
        candidate_id="C-misc-docker",
        value=MISC_CANDIDATE,
    )

    final, evaluation = engine.evaluate_misc_transform_candidate(
        identity,
        "C-misc-docker",
        spec_locator="misc-spec.json",
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
    if (
        evaluation.passed is not True
        or candidate.status is not CandidateStatus.OBSERVED_CANDIDATE
        or candidate.proof_run_ids
        or not isinstance(run_ids, list)
        or len(run_ids) != 4
        or final.submissions
    ):
        raise AssertionError(
            "Misc ChallengeEngine Docker hot path did not prove DAG+3"
        )
    return {
        "candidate_status": candidate.status.value,
        "network": "none",
        "runs": len(run_ids),
        "submissions": len(final.submissions),
        "transform_evidence_passed": evaluation.passed,
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
