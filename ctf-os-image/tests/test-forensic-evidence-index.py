#!/usr/bin/env python3
"""Regression tests for the bounded forensic evidence index producer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = pathlib.Path(__file__).resolve().parent.parent
MODULE_PATH = (
    REPOSITORY / "templates" / "forensic" / "evidence_index.py"
)
SPEC = importlib.util.spec_from_file_location(
    "forensic_evidence_index_under_test",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _provenance(
    root: pathlib.Path,
    metadata_path: pathlib.Path,
    tree_path: pathlib.Path,
) -> None:
    entries: list[tuple[bytes, bytes, bytes, bytes | None]] = []
    total_bytes = 0
    file_count = 0
    for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item.relative_to(root))):
        relative = os.fsencode(path.relative_to(root).as_posix())
        mode = f"{stat.S_IMODE(path.lstat().st_mode):o}".encode("ascii")
        if path.is_symlink():
            target = os.fsencode(os.readlink(path))
            digest = hashlib.sha256(path.resolve().read_bytes()).hexdigest().encode(
                "ascii"
            )
            entries.append((b"L", mode, relative, target + b"\x00" + digest))
            file_count += 1
            total_bytes += path.lstat().st_size
        elif path.is_dir():
            entries.append((b"D", mode, relative, None))
        else:
            digest = _sha256(path).encode("ascii")
            entries.append((b"F", mode, relative, digest))
            file_count += 1
            total_bytes += path.stat().st_size
    tree = bytearray()
    for kind, mode, relative, trailing in entries:
        tree.extend(kind + b"\x00" + mode + b"\x00" + relative + b"\x00")
        if trailing is not None:
            tree.extend(trailing + b"\x00")
    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_bytes(bytes(tree))
    tree_digest = hashlib.sha256(tree).hexdigest()
    metadata_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "initialized",
                "source": {
                    "path": str(root.resolve()),
                    "present": True,
                    "read_only_expected": True,
                    "mount_read_only": True,
                    "writable_override_used": False,
                },
                "inventory": {
                    "algorithm": "sha256",
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                },
                "tree": {
                    "format": "ctf-tree-v1-nul",
                    "path": str(tree_path),
                    "digest": tree_digest,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


class ForensicEvidenceIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temporary.name)
        self.root = self.base / "challenge"
        self.root.mkdir()
        self.metadata = self.base / "work" / ".ctf" / "challenge.json"
        self.tree = self.base / "work" / ".ctf" / "challenge.tree"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_index_is_deterministic_typed_and_hash_bound(self) -> None:
        packets = self.root / "traffic.pcapng"
        packets.write_bytes(b"\x0a\x0d\x0d\x0a" + b"P" * 32)
        nested = self.root / "nested"
        nested.mkdir()
        event_log = nested / "security.evtx"
        event_log.write_bytes(b"ElfFile\x00" + b"E" * 24)
        _provenance(self.root, self.metadata, self.tree)

        first = MODULE.build_evidence_index(
            self.root,
            self.tree,
            self.metadata,
        )
        second = MODULE.build_evidence_index(
            self.root,
            self.tree,
            self.metadata,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first["contract"],
            {"id": "ctfos.forensic.evidence_index", "version": 1},
        )
        self.assertEqual(
            first["coverage"],
            {
                "hash_bound_files": 2,
                "indexed_bytes": packets.stat().st_size + event_log.stat().st_size,
                "indexed_files": 2,
                "pointer_coverage_ppm": 1_000_000,
                "pointer_records_emitted": 2,
                "pointer_records_total": 2,
                "prefix_probed_files": 2,
                "projection": "complete",
                "records_truncated": False,
            },
        )
        by_path = {
            record["pointer"]["path"]: record
            for record in first["records"]
        }
        packet_record = by_path[str(packets.resolve())]
        event_record = by_path[str(event_log.resolve())]
        self.assertEqual(packet_record["pointer"]["sha256"], _sha256(packets))
        self.assertEqual(
            packet_record["classification"],
            {
                "basis": "magic",
                "format": "pcapng",
                "modality": "network",
            },
        )
        self.assertEqual(
            event_record["classification"]["modality"],
            "event_log",
        )
        self.assertEqual(
            packet_record["timestamp"]["timezone_status"],
            "unknown",
        )
        self.assertEqual(
            packet_record["parent_evidence_id"],
            first["graph"]["root_evidence_id"],
        )
        chain = hashlib.sha256()
        for record in first["records"]:
            chain.update(MODULE._canonical_json(record))
            chain.update(b"\n")
        self.assertEqual(first["index_sha256"], chain.hexdigest())

    def test_projection_limit_is_explicit_but_full_chain_is_preserved(
        self,
    ) -> None:
        for ordinal in range(3):
            (self.root / f"{ordinal}.log").write_text(
                f"event {ordinal}\n",
                encoding="utf-8",
            )
        _provenance(self.root, self.metadata, self.tree)

        complete = MODULE.build_evidence_index(
            self.root,
            self.tree,
            self.metadata,
        )
        bounded = MODULE.build_evidence_index(
            self.root,
            self.tree,
            self.metadata,
            max_emitted_records=1,
        )

        self.assertEqual(bounded["coverage"]["indexed_files"], 3)
        self.assertEqual(bounded["coverage"]["pointer_records_emitted"], 1)
        self.assertEqual(bounded["coverage"]["projection"], "partial")
        self.assertTrue(bounded["coverage"]["records_truncated"])
        self.assertEqual(bounded["index_sha256"], complete["index_sha256"])

    def test_changed_tree_is_rejected_before_source_probe(self) -> None:
        (self.root / "evidence.bin").write_bytes(b"evidence")
        _provenance(self.root, self.metadata, self.tree)
        self.tree.write_bytes(self.tree.read_bytes() + b"tamper")

        with self.assertRaisesRegex(
            MODULE.EvidenceIndexError,
            "provenance_binding_invalid",
        ):
            MODULE.build_evidence_index(
                self.root,
                self.tree,
                self.metadata,
            )

    def test_same_size_source_change_after_provenance_is_rejected(
        self,
    ) -> None:
        evidence = self.root / "evidence.bin"
        evidence.write_bytes(b"original")
        _provenance(self.root, self.metadata, self.tree)
        evidence.write_bytes(b"tampered")

        with self.assertRaisesRegex(
            MODULE.EvidenceIndexError,
            "source_hash_mismatch",
        ):
            MODULE.build_evidence_index(
                self.root,
                self.tree,
                self.metadata,
            )

    def test_path_traversal_and_symlinks_fail_closed(self) -> None:
        outside = self.base / "outside"
        outside.write_bytes(b"outside")
        link = self.root / "link"
        link.symlink_to(outside)
        _provenance(self.root, self.metadata, self.tree)

        with self.assertRaisesRegex(
            MODULE.EvidenceIndexError,
            "tree_symlink_unsupported",
        ):
            MODULE.build_evidence_index(
                self.root,
                self.tree,
                self.metadata,
            )

        link.unlink()
        self.tree.write_bytes(
            b"F\x00644\x00../outside\x00"
            + hashlib.sha256(b"outside").hexdigest().encode("ascii")
            + b"\x00"
        )
        metadata = json.loads(self.metadata.read_text(encoding="utf-8"))
        metadata["inventory"]["file_count"] = 1
        metadata["inventory"]["total_bytes"] = len(b"outside")
        metadata["tree"]["digest"] = hashlib.sha256(
            self.tree.read_bytes()
        ).hexdigest()
        self.metadata.write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            MODULE.EvidenceIndexError,
            "tree_path_invalid",
        ):
            MODULE.build_evidence_index(
                self.root,
                self.tree,
                self.metadata,
            )

    def test_cli_emits_one_canonical_json_document(self) -> None:
        evidence = self.root / "mail.eml"
        evidence.write_bytes(b"From: sender@example.test\n\nbody\n")
        _provenance(self.root, self.metadata, self.tree)

        completed = subprocess.run(
            (
                sys.executable,
                str(MODULE_PATH),
                "--root",
                str(self.root),
                "--tree",
                str(self.tree),
                "--metadata",
                str(self.metadata),
            ),
            check=False,
            capture_output=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(completed.stdout.count(b"\n"), 1)
        decoded = json.loads(completed.stdout)
        self.assertEqual(
            decoded["records"][0]["classification"]["modality"],
            "mail",
        )
        self.assertEqual(
            completed.stdout,
            MODULE._canonical_json(decoded) + b"\n",
        )


if __name__ == "__main__":
    unittest.main()
