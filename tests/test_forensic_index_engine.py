from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from ctf_os.engine.forensic_index import (
    ForensicIndexVerdict,
    ForensicSourceExpectation,
    evaluate_forensic_evidence_index,
)


REPOSITORY = Path(__file__).resolve().parent.parent
PRODUCER_PATH = (
    REPOSITORY / "ctf-os-image/templates/forensic/evidence_index.py"
)
SPEC = importlib.util.spec_from_file_location(
    "forensic_index_producer_for_engine_test",
    PRODUCER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PRODUCER
SPEC.loader.exec_module(PRODUCER)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_provenance(
    root: Path,
    metadata_path: Path,
    tree_path: Path,
) -> None:
    tree = bytearray()
    file_count = 0
    total_bytes = 0
    for path in sorted(
        root.rglob("*"),
        key=lambda item: os.fsencode(item.relative_to(root).as_posix()),
    ):
        relative = path.relative_to(root).as_posix().encode()
        mode = f"{stat.S_IMODE(path.stat().st_mode):o}".encode()
        if path.is_dir():
            tree.extend(b"D\0" + mode + b"\0" + relative + b"\0")
            continue
        payload = path.read_bytes()
        tree.extend(
            b"F\0"
            + mode
            + b"\0"
            + relative
            + b"\0"
            + _sha256(payload).encode()
            + b"\0"
        )
        file_count += 1
        total_bytes += len(payload)
    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_bytes(tree)
    metadata_path.write_text(
        json.dumps(
            {
                "inventory": {
                    "algorithm": "sha256",
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                },
                "schema_version": 1,
                "source": {
                    "mount_read_only": True,
                    "path": str(root),
                    "present": True,
                    "read_only_expected": True,
                    "writable_override_used": False,
                },
                "status": "initialized",
                "tree": {
                    "digest": _sha256(bytes(tree)),
                    "format": "ctf-tree-v1-nul",
                    "path": str(tree_path),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


class ForensicIndexEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "challenge"
        self.root.mkdir()
        (self.root / "traffic.pcapng").write_bytes(
            b"\x0a\x0d\x0d\x0a" + b"packet"
        )
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "case.evtx").write_bytes(b"ElfFile\0event")
        self.metadata = self.base / "work/.ctf/challenge.json"
        self.tree = self.base / "work/.ctf/challenge.tree"
        _write_provenance(self.root, self.metadata, self.tree)
        self.document = PRODUCER.build_evidence_index(
            self.root, self.tree, self.metadata
        )
        self.payload = PRODUCER._canonical_json(self.document) + b"\n"
        self.sources = tuple(
            ForensicSourceExpectation(
                path=path.relative_to(self.root).as_posix(),
                sha256=_sha256(path.read_bytes()),
                size_bytes=path.stat().st_size,
                prefix_sha256=_sha256(path.read_bytes()[:4096]),
                prefix_size_bytes=min(path.stat().st_size, 4096),
            )
            for path in sorted(
                (item for item in self.root.rglob("*") if item.is_file()),
                key=lambda item: item.relative_to(self.root).as_posix().encode(),
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _evaluate(self, payload: bytes | None = None):
        return evaluate_forensic_evidence_index(
            self.payload if payload is None else payload,
            self.sources,
            expected_source_root=str(self.root),
        )

    def test_complete_producer_output_is_confirmed_and_raw_free(self) -> None:
        result = self._evaluate()

        self.assertIs(result.verdict, ForensicIndexVerdict.CONFIRMED)
        self.assertEqual(result.reason_code, "complete_hash_bound_index")
        self.assertEqual(result.indexed_files, 2)
        self.assertEqual(result.pointer_coverage_ppm, 1_000_000)
        persisted = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn(str(self.root), persisted)
        self.assertNotIn("traffic.pcapng", persisted)
        self.assertTrue(
            result.to_dict()["claims"]["evidence_index_verified"]
        )
        self.assertFalse(
            result.to_dict()["claims"]["challenge_proof_satisfied"]
        )

    def test_tampered_pointer_prefix_and_index_fail_closed(self) -> None:
        cases = []
        pointer = copy.deepcopy(self.document)
        pointer["records"][0]["pointer"]["sha256"] = "f" * 64
        cases.append((pointer, "record_binding_invalid"))
        prefix = copy.deepcopy(self.document)
        prefix["records"][0]["prefix_probe"]["sha256"] = "e" * 64
        cases.append((prefix, "record_binding_invalid"))
        index = copy.deepcopy(self.document)
        index["index_sha256"] = "d" * 64
        cases.append((index, "index_commitment_invalid"))
        for document, reason in cases:
            with self.subTest(reason=reason):
                result = self._evaluate(
                    PRODUCER._canonical_json(document) + b"\n"
                )
                self.assertIs(
                    result.verdict, ForensicIndexVerdict.REJECTED
                )
                self.assertEqual(result.reason_code, reason)

    def test_partial_projection_and_record_reorder_are_rejected(self) -> None:
        partial = copy.deepcopy(self.document)
        partial["records"] = partial["records"][:1]
        partial["coverage"]["pointer_records_emitted"] = 1
        partial["coverage"]["projection"] = "partial"
        partial["coverage"]["records_truncated"] = True
        reordered = copy.deepcopy(self.document)
        reordered["records"].reverse()
        for document, reason in (
            (partial, "coverage_incomplete"),
            (reordered, "record_binding_invalid"),
        ):
            with self.subTest(reason=reason):
                result = self._evaluate(
                    PRODUCER._canonical_json(document) + b"\n"
                )
                self.assertEqual(result.reason_code, reason)

    def test_noncanonical_and_duplicate_json_are_rejected(self) -> None:
        noncanonical = json.dumps(self.document, indent=2).encode()
        duplicate = self.payload.replace(
            b'{"contract":',
            b'{"schema_version":1,"contract":',
            1,
        )
        self.assertEqual(
            self._evaluate(noncanonical).reason_code,
            "noncanonical_json",
        )
        self.assertEqual(
            self._evaluate(duplicate).reason_code,
            "invalid_json",
        )


if __name__ == "__main__":
    unittest.main()
