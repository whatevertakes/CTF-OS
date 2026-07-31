from __future__ import annotations

import ast
import hashlib
import tempfile
import unittest
from pathlib import Path

from ctf_os.engine import pwn_interaction_hotpath
from ctf_os.engine import web_impact_hotpath
from ctf_os.models import ChallengeIdentity


REPOSITORY = Path(__file__).resolve().parent.parent
HOTPATHS = (
    "data_transcript_hotpath.py",
    "forensic_assertion_hotpath.py",
    "pwn_exploit_effect_hotpath.py",
    "pwn_interaction_hotpath.py",
    "rev_acceptance_hotpath.py",
    "rev_runtime_proof.py",
    "web_active_probe_hotpath.py",
    "web_impact_hotpath.py",
)


class _AdmissionBudget:
    def __init__(self, remaining: int) -> None:
        self.remaining = remaining
        self.calls: list[int] = []

    def __call__(self, size: int) -> None:
        self.calls.append(size)
        if size > self.remaining:
            raise RuntimeError("challenge storage quota exceeded")
        self.remaining -= size


class _Engine:
    def __init__(self, budget: _AdmissionBudget) -> None:
        self.budget = budget

    def _enforce_storage_admission(
        self,
        _identity: ChallengeIdentity,
        *,
        requested_bytes: int | None = None,
    ) -> dict[str, object]:
        if requested_bytes is None:
            raise AssertionError("exact byte admission required")
        self.budget(requested_bytes)
        return {}


class HotPathStorageAdmissionTests(unittest.TestCase):
    def test_duplicate_copy_consumes_exact_cumulative_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"same-source"
            source = root / "source.bin"
            source.write_bytes(payload)
            snapshot = web_impact_hotpath._Snapshot(
                artifact_id="A-source",
                path="source.bin",
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                source_locator="source.bin",
                role="input",
            )
            budget = _AdmissionBudget(2 * len(payload))

            for name in ("first.bin", "second.bin"):
                web_impact_hotpath._copy_snapshot_to_workspace(
                    root,
                    snapshot,
                    root / "copies" / name,
                    source_size_admission=budget,
                )

            self.assertEqual(budget.calls, [len(payload), len(payload)])
            self.assertEqual(budget.remaining, 0)
            self.assertEqual(
                (root / "copies" / "first.bin").read_bytes(),
                payload,
            )
            self.assertEqual(
                (root / "copies" / "second.bin").read_bytes(),
                payload,
            )

    def test_quota_reject_precedes_artifact_parent_and_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = ChallengeIdentity("contest", "pwn", "challenge")
            budget = _AdmissionBudget(3)
            destination = root / "new-parent" / "artifact.bin"

            with self.assertRaisesRegex(RuntimeError, "quota exceeded"):
                pwn_interaction_hotpath._artifact_from_bytes(
                    engine=_Engine(budget),
                    identity=identity,
                    artifact_id="A-test",
                    destination=destination,
                    root=root,
                    payload=b"four",
                    run_id=None,
                    kind="test",
                    attempt_id="attempt",
                )

            self.assertEqual(budget.calls, [4])
            self.assertFalse(destination.exists())
            self.assertFalse(destination.parent.exists())
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_every_direct_hotpath_copy_has_size_admission(self) -> None:
        for name in HOTPATHS:
            path = REPOSITORY / "ctf_os" / "engine" / name
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func
                if not (
                    isinstance(called, ast.Name)
                    and called.id == "copy_bounded_regular"
                ):
                    continue
                with self.subTest(path=name, line=node.lineno):
                    self.assertIn(
                        "source_size_admission",
                        {item.arg for item in node.keywords},
                    )


if __name__ == "__main__":
    unittest.main()
