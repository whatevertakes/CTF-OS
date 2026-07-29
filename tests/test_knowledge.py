from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ctf_os.knowledge as knowledge_module
from ctf_os import cli
from ctf_os.adapters import get_adapter
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.knowledge import (
    MAX_KNOWLEDGE_READ_BYTES,
    KnowledgeError,
    KnowledgeStore,
)
from ctf_os.models import ChallengeIdentity


class KnowledgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("KCTF", "crypto", "research")
        self.engine = ChallengeEngine(self.root)
        self.state = self.engine.add_challenge(
            self.identity,
            prompt="공개 원문 근거와 함께 취약점을 분석하라",
        )
        self.store = KnowledgeStore(self.engine.store)
        self.source = self.root / "paper.md"
        self.source.write_text(
            "# Full paper\n\n"
            "Coppersmith lattice bounds require parameter validation. "
            "The complete derivation and experiment details are preserved.\n",
            encoding="utf-8",
        )
        self.source_url = "https://arxiv.org/abs/2601.09129"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_add_is_immutable_deduplicated_and_searchable(self) -> None:
        expected = hashlib.sha256(self.source.read_bytes()).hexdigest()
        record = self.store.add(
            self.identity,
            self.source,
            source_url=self.source_url,
            title="KryptoPilot full text",
            expected_sha256=expected,
        )
        root = self.engine.store.challenge_paths(self.identity).knowledge
        snapshot = root / record.document_path
        text = root / str(record.text_path)
        self.assertEqual(snapshot.read_bytes(), self.source.read_bytes())
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
        self.assertEqual(text.stat().st_mode & 0o777, 0o400)

        self.source.write_text("mutated operator copy\n", encoding="utf-8")
        self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), expected)
        duplicate_source = self.root / "paper-copy.md"
        duplicate_source.write_bytes(snapshot.read_bytes())
        duplicate = self.store.add(
            self.identity,
            duplicate_source,
            source_url=self.source_url,
            title="duplicate title",
        )
        self.assertEqual(duplicate.id, record.id)
        self.assertEqual(len(self.store.list(self.identity)), 1)

        results = self.store.search(self.identity, "Coppersmith parameter")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].id, record.id)
        self.assertIn("Coppersmith", results[0][2])

    def test_add_interrupt_cleans_before_and_preserves_after_index_commit(
        self,
    ) -> None:
        knowledge_root = self.engine.store.challenge_paths(
            self.identity
        ).knowledge
        documents = knowledge_root / "documents"
        text_root = knowledge_root / "text"
        real_copy = knowledge_module.copy_bounded_regular
        copy_interrupt = KeyboardInterrupt("after knowledge copy")

        def interrupt_after_copy(*args, **kwargs):
            real_copy(*args, **kwargs)
            raise copy_interrupt

        with (
            patch.object(
                knowledge_module,
                "copy_bounded_regular",
                side_effect=interrupt_after_copy,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.store.add(
                self.identity,
                self.source,
                source_url=self.source_url,
            )
        self.assertIs(raised.exception, copy_interrupt)
        self.assertEqual(self.store.list(self.identity), ())
        self.assertEqual(list(documents.glob("K-*.bin")), [])
        self.assertEqual(list(text_root.glob("K-*.txt")), [])

        real_write_text = knowledge_module.atomic_write_text
        text_interrupt = KeyboardInterrupt("after knowledge text")

        def interrupt_after_text(*args, **kwargs):
            real_write_text(*args, **kwargs)
            raise text_interrupt

        with (
            patch.object(
                knowledge_module,
                "atomic_write_text",
                side_effect=interrupt_after_text,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.store.add(
                self.identity,
                self.source,
                source_url=self.source_url,
            )
        self.assertIs(raised.exception, text_interrupt)
        self.assertEqual(self.store.list(self.identity), ())
        self.assertEqual(list(documents.glob("K-*.bin")), [])
        self.assertEqual(list(text_root.glob("K-*.txt")), [])

        real_write_index = knowledge_module._write_index
        commit_interrupt = KeyboardInterrupt("after knowledge index commit")

        def interrupt_after_index(*args, **kwargs):
            real_write_index(*args, **kwargs)
            raise commit_interrupt

        with (
            patch.object(
                knowledge_module,
                "_write_index",
                side_effect=interrupt_after_index,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.store.add(
                self.identity,
                self.source,
                source_url=self.source_url,
            )
        self.assertIs(raised.exception, commit_interrupt)
        records = self.store.list(self.identity)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue((knowledge_root / record.document_path).is_file())
        self.assertTrue((knowledge_root / str(record.text_path)).is_file())

    def test_add_lock_acquire_return_interrupt_releases_and_recovers(
        self,
    ) -> None:
        challenge_paths = self.engine.store.challenge_paths(self.identity)
        knowledge_root = challenge_paths.knowledge
        state_path = challenge_paths.state
        lock_path = knowledge_root / ".lock"
        index_path = knowledge_root / "index.json"
        documents = knowledge_root / "documents"
        text_root = knowledge_root / "text"
        acquire_code = knowledge_module.FileLock.acquire.__code__

        for ordinal, interruption in enumerate(
            (
                KeyboardInterrupt(
                    "synthetic knowledge lock acquire return interrupt"
                ),
                SystemExit(
                    "synthetic knowledge lock acquire return exit"
                ),
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                source = self.root / f"handoff-{ordinal}.md"
                source.write_text(
                    f"reviewed handoff evidence {ordinal}\n",
                    encoding="utf-8",
                )
                source_url = (
                    f"https://example.test/handoff-{ordinal}"
                )
                records_before = self.store.list(self.identity)
                state_before = state_path.read_bytes()
                index_before = (
                    index_path.read_bytes()
                    if index_path.exists()
                    else None
                )
                documents_before = {
                    path.name for path in documents.glob("K-*.bin")
                }
                text_before = {
                    path.name for path in text_root.glob("K-*.txt")
                }
                injected = False

                def interrupt_acquire_return(frame, event, argument):
                    nonlocal injected
                    owner = frame.f_locals.get("self")
                    if (
                        not injected
                        and frame.f_code is acquire_code
                        and event == "return"
                        and argument is owner
                        and getattr(owner, "path", None) == lock_path
                    ):
                        injected = True
                        sys.settrace(None)
                        raise interruption
                    return interrupt_acquire_return

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_acquire_return)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        self.store.add(
                            self.identity,
                            source,
                            source_url=source_url,
                        )
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                interruption.__traceback__ = None
                self.assertEqual(
                    self.store.list(self.identity),
                    records_before,
                )
                self.assertEqual(state_path.read_bytes(), state_before)
                self.assertEqual(
                    (
                        index_path.read_bytes()
                        if index_path.exists()
                        else None
                    ),
                    index_before,
                )
                self.assertEqual(
                    {
                        path.name
                        for path in documents.glob("K-*.bin")
                    },
                    documents_before,
                )
                self.assertEqual(
                    {
                        path.name
                        for path in text_root.glob("K-*.txt")
                    },
                    text_before,
                )

                recovered = self.store.add(
                    self.identity,
                    source,
                    source_url=source_url,
                )
                records_after = self.store.list(self.identity)
                self.assertEqual(
                    len(records_after),
                    len(records_before) + 1,
                )
                self.assertIn(recovered, records_after)

    def test_context_contains_bounded_source_hash_and_excerpt(self) -> None:
        record = self.store.add(
            self.identity,
            self.source,
            source_url=self.source_url,
            title="KryptoPilot",
        )
        pack = build_context_pack(
            self.engine.store.load(self.identity),
            get_adapter("crypto"),
            state_path=self.engine.store.challenge_paths(self.identity).state,
        )
        self.assertIn("Operator-ingested research with provenance", pack.text)
        self.assertIn(record.sha256, pack.text)
        self.assertIn(self.source_url, pack.text)
        self.assertIn("Coppersmith", pack.text)

        snapshot = (
            self.engine.store.challenge_paths(self.identity).knowledge
            / record.document_path
        )
        snapshot.chmod(0o600)
        snapshot.write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeError, "mismatch"):
            self.store.search(self.identity, "Coppersmith")
        tampered_pack = build_context_pack(
            self.engine.store.load(self.identity),
            get_adapter("crypto"),
            state_path=self.engine.store.challenge_paths(self.identity).state,
        )
        self.assertIn("knowledge index unavailable", tampered_pack.text)
        self.assertNotIn("Coppersmith", tampered_pack.text)

    def test_read_is_hash_verified_utf8_paginated_and_capped(self) -> None:
        self.source.write_text("가나다라마바사\nASCII-tail\n", encoding="utf-8")
        record = self.store.add(
            self.identity,
            self.source,
            source_url=self.source_url,
            title="UTF-8 pagination",
        )

        first = self.store.read(
            self.identity,
            record.id,
            max_bytes=4,
        )
        self.assertEqual(first.text, "가")
        self.assertEqual(first.offset_bytes, 0)
        self.assertEqual(first.returned_bytes, len("가".encode("utf-8")))
        self.assertEqual(first.next_offset_bytes, 3)
        second = self.store.read(
            self.identity,
            record.id,
            offset_bytes=first.next_offset_bytes,
            max_bytes=6,
        )
        self.assertEqual(second.text, "나다")
        self.assertEqual(second.offset_bytes, 3)
        self.assertLessEqual(
            len(
                json.dumps(
                    second.to_dict(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            1024 * 1024,
        )

        with self.assertRaisesRegex(KnowledgeError, "UTF-8 boundary"):
            self.store.read(self.identity, record.id, offset_bytes=1)
        with self.assertRaisesRegex(KnowledgeError, "65536"):
            self.store.read(
                self.identity,
                record.id,
                max_bytes=MAX_KNOWLEDGE_READ_BYTES + 1,
            )

        knowledge_root = self.engine.store.challenge_paths(
            self.identity
        ).knowledge
        text_path = knowledge_root / str(record.text_path)
        text_path.chmod(0o600)
        text_path.write_text("tampered text\n", encoding="utf-8")
        with self.assertRaisesRegex(KnowledgeError, "mismatch"):
            self.store.read(self.identity, record.id)

    def test_search_envelope_has_bounded_source_and_hash_provenance(self) -> None:
        record = self.store.add(
            self.identity,
            self.source,
            source_url=self.source_url,
            title="KryptoPilot",
        )
        envelope = self.store.search_envelope(
            self.identity,
            "Coppersmith lattice",
            limit=1,
        )
        self.assertEqual(envelope["schema_version"], 1)
        self.assertEqual(envelope["returned"], 1)
        result = envelope["results"][0]
        self.assertEqual(result["document"]["id"], record.id)
        self.assertEqual(result["document"]["sha256"], record.sha256)
        self.assertEqual(result["document"]["source_url"], self.source_url)
        self.assertIn("Coppersmith", result["excerpt"])
        self.assertGreaterEqual(result["excerpt_offset_bytes"], 0)
        self.assertLess(
            len(
                json.dumps(
                    envelope,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            1024 * 1024,
        )

    def test_context_retrieves_query_match_beyond_the_old_first_4k(self) -> None:
        marker = "rare_widget_oracle"
        self.source.write_text(
            "HEAD_ONLY_SHOULD_NOT_APPEAR\n"
            + ("filler_segment " * 700)
            + f"\n{marker} gives the exploit constraint\n",
            encoding="utf-8",
        )
        self.store.add(
            self.identity,
            self.source,
            source_url=self.source_url,
            title="Long reviewed notes",
        )
        self.engine.update_prompt(
            self.identity,
            f"Locate and apply {marker}.",
        )
        pack = build_context_pack(
            self.engine.store.load(self.identity),
            get_adapter("crypto"),
            state_path=self.engine.store.challenge_paths(self.identity).state,
        )
        knowledge_section = pack.text.split(
            "## Operator-ingested research with provenance", 1
        )[1].split("## Category progress and failure contract", 1)[0]
        self.assertIn(marker, knowledge_section)
        self.assertNotIn("HEAD_ONLY_SHOULD_NOT_APPEAR", knowledge_section)
        offset_text = knowledge_section.split(
            "excerpt_offset_bytes=", 1
        )[1].split(";", 1)[0]
        self.assertGreater(int(offset_text), 4_000)

    def test_rejects_bad_hash_symlink_fifo_and_credential_url(self) -> None:
        with self.assertRaisesRegex(KnowledgeError, "hash changed"):
            self.store.add(
                self.identity,
                self.source,
                source_url=self.source_url,
                expected_sha256="0" * 64,
            )
        symlink = self.root / "paper-link.md"
        symlink.symlink_to(self.source)
        with self.assertRaisesRegex(KnowledgeError, "non-symlink"):
            self.store.add(
                self.identity,
                symlink,
                source_url=self.source_url,
            )
        fifo = self.root / "paper.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(KnowledgeError, "regular"):
            self.store.add(
                self.identity,
                fifo,
                source_url=self.source_url,
            )
        with self.assertRaisesRegex(KnowledgeError, "credentials"):
            self.store.add(
                self.identity,
                self.source,
                source_url="https://user:secret@example.test/paper",
            )
        for source_url in (
            "https://example.test/paper?token=secret",
            "https://example.test/paper#private-note",
        ):
            with self.subTest(source_url=source_url), self.assertRaisesRegex(
                KnowledgeError,
                "query, or fragment",
            ):
                self.store.add(
                    self.identity,
                    self.source,
                    source_url=source_url,
                )

    def test_cli_add_list_and_search_never_download(self) -> None:
        expected = hashlib.sha256(self.source.read_bytes()).hexdigest()

        def invoke(arguments: list[str]) -> tuple[int, str, str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(arguments, root=self.root)
            return status, stdout.getvalue(), stderr.getvalue()

        status, output, errors = invoke(
            [
                "knowledge",
                "add",
                self.identity.contest_id,
                self.identity.category,
                self.identity.challenge_id,
                str(self.source),
                "--source",
                self.source_url,
                "--sha256",
                expected,
                "--title",
                "reviewed paper",
            ]
        )
        self.assertEqual(status, 0, errors)
        record = json.loads(output)
        self.assertEqual(record["sha256"], expected)

        status, output, errors = invoke(
            [
                "knowledge",
                "list",
                self.identity.contest_id,
                self.identity.category,
                self.identity.challenge_id,
            ]
        )
        self.assertEqual(status, 0, errors)
        self.assertEqual(len(json.loads(output)), 1)

        status, output, errors = invoke(
            [
                "knowledge",
                "search",
                self.identity.contest_id,
                self.identity.category,
                self.identity.challenge_id,
                "lattice bounds",
            ]
        )
        self.assertEqual(status, 0, errors)
        self.assertEqual(len(json.loads(output)), 1)


if __name__ == "__main__":
    unittest.main()
