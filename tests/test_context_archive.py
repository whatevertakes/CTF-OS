from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.codex import (
    BatchRunner,
    FifoModelCallLimiter,
    ProcessOutcome,
    Role,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.context_archive import (
    ContextArchiveConflict,
    archive_context_pack,
)
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.models import ChallengeIdentity


def _output_path(command) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


class _ReconExecutor:
    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, timeout, on_stdout_line
        _output_path(command).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "role": Role.RECON.value,
                    "status": "ok",
                    "summary": "bounded context archive integration",
                    "observations": [],
                    "hypotheses": [],
                    "hypothesis_updates": [],
                    "evaluations": [],
                    "actions": [],
                    "artifacts": [],
                    "progress_markers": [],
                    "flag_candidates": [],
                    "decision": None,
                    "goal_update": None,
                    "refusal": None,
                }
            ),
            encoding="utf-8",
        )
        return ProcessOutcome(0, "", 0.01)


class ContextArchiveTests(unittest.TestCase):
    def test_archive_is_idempotent_but_refuses_conflicting_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "context" / "history"
            text = '{"kind":"bounded"}\n'
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

            first = archive_context_pack(
                history,
                run_id="run-1",
                text=text,
                expected_sha256=digest,
            )
            second = archive_context_pack(
                history,
                run_id="run-1",
                text=text,
                expected_sha256=digest,
            )

            self.assertEqual(first, second)
            self.assertEqual(first.path.read_text(encoding="utf-8"), text)
            conflicting = '{"kind":"different"}\n'
            with self.assertRaises(ContextArchiveConflict):
                archive_context_pack(
                    history,
                    run_id="run-1",
                    text=conflicting,
                    expected_sha256=hashlib.sha256(
                        conflicting.encode("utf-8")
                    ).hexdigest(),
                )
            self.assertEqual(first.path.read_text(encoding="utf-8"), text)

    def test_model_run_records_exact_context_history_pointer_and_hash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = ChallengeIdentity("contest", "rev", "challenge")
            runner = BatchRunner(
                process_executor=_ReconExecutor(),
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            )
            engine = ChallengeEngine(root, batch_runner=runner)
            before = engine.add_challenge(identity, prompt="solve exactly")
            expected = build_context_pack(
                before,
                get_adapter(before.category),
                state_path=engine.store.challenge_paths(identity).state,
                role=Role.RECON.value,
            )

            result = engine.run_role(
                identity,
                Role.RECON,
                instruction="instruction must not enter context history",
            )

            paths = engine.store.challenge_paths(identity)
            run_paths = engine.store.run_paths(
                identity,
                run_id=result.invocation.run_id,
            )
            request = json.loads(
                run_paths.request.read_text(encoding="utf-8")
            )
            archive_path = paths.root / request["context_path"]
            archive_bytes = archive_path.read_bytes()
            state = engine.store.load(identity)
            run = next(
                item
                for item in state.runs
                if item.id == result.invocation.run_id
            )

            self.assertEqual(archive_path.parent, paths.context_history)
            self.assertEqual(archive_bytes.decode("utf-8"), expected.text)
            self.assertNotIn(
                "instruction must not enter context history",
                archive_bytes.decode("utf-8"),
            )
            self.assertEqual(
                hashlib.sha256(archive_bytes).hexdigest(),
                expected.sha256,
            )
            self.assertEqual(request["context_sha256"], expected.sha256)
            self.assertEqual(
                request["context_size_bytes"],
                len(archive_bytes),
            )
            self.assertEqual(run.context_hash, expected.sha256)
            self.assertEqual(
                run.extra["context_path"],
                request["context_path"],
            )
            self.assertEqual(
                stat.S_IMODE(archive_path.stat().st_mode),
                0o600,
            )


if __name__ == "__main__":
    unittest.main()
