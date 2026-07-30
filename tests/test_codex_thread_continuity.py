from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_os.codex.commands import BatchInvocation, BuiltCommand
from ctf_os.codex.contracts import Role
from ctf_os.codex.runner import BatchRunner, ProcessOutcome


class _RecordingBuilder:
    def __init__(self) -> None:
        self.resume_ids: list[str | None] = []

    def build(
        self,
        invocation,
        schema_path,
        output_path,
        *,
        resume_thread_id=None,
        correction=None,
    ) -> BuiltCommand:
        del invocation, schema_path, correction
        self.resume_ids.append(resume_thread_id)
        output_path.write_text("{}\n", encoding="utf-8")
        return BuiltCommand(("fake-codex",), "prompt")


class _SequencedExecutor:
    def __init__(self, returncodes: tuple[int, ...]) -> None:
        self.returncodes = list(returncodes)

    def run(
        self,
        command,
        *,
        cwd,
        timeout,
        on_stdout_line,
    ) -> ProcessOutcome:
        del command, cwd, timeout, on_stdout_line
        return ProcessOutcome(
            returncode=self.returncodes.pop(0),
            stderr="",
            duration_seconds=0.01,
        )


class CodexThreadContinuityTests(unittest.TestCase):
    def _invocation(
        self,
        root: Path,
        *,
        resume_thread_id: str | None,
    ) -> BatchInvocation:
        work = root / "work"
        output = root / "output"
        work.mkdir(parents=True)
        output.mkdir()
        return BatchInvocation(
            run_id="MR-continuity",
            role=Role.CAPTAIN,
            prompt="continue one bounded challenge",
            working_directory=work,
            output_directory=output,
            contract_version=2,
            resume_thread_id=resume_thread_id,
        )

    def test_invocation_rejects_nonopaque_thread_identifiers(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-thread-id-"
        ) as temporary:
            root = Path(temporary)
            for invalid in (
                "",
                "thread with spaces",
                "../thread",
                "thread/child",
                "x" * 257,
            ):
                with self.subTest(invalid=invalid):
                    with self.assertRaisesRegex(
                        ValueError,
                        "resume_thread_id",
                    ):
                        self._invocation(
                            root / str(len(invalid)),
                            resume_thread_id=invalid,
                        )

    def test_initial_resume_survives_schema_retry_without_new_thread_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-thread-continuity-"
        ) as temporary:
            builder = _RecordingBuilder()
            runner = BatchRunner(
                command_builder=builder,
                process_executor=_SequencedExecutor((0, 1)),
                max_schema_retries=1,
            )
            invocation = self._invocation(
                Path(temporary),
                resume_thread_id="019fb499-3d76-7ef1-80f4-cf02f088e74c",
            )

            result = runner.run(invocation)

            self.assertEqual(
                builder.resume_ids,
                [
                    invocation.resume_thread_id,
                    invocation.resume_thread_id,
                ],
            )
            self.assertEqual(result.thread_id, invocation.resume_thread_id)
            self.assertEqual(len(result.attempts), 2)

    def test_fresh_invocation_remains_fresh(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-thread-fresh-"
        ) as temporary:
            builder = _RecordingBuilder()
            runner = BatchRunner(
                command_builder=builder,
                process_executor=_SequencedExecutor((1,)),
                max_schema_retries=0,
            )
            invocation = self._invocation(
                Path(temporary),
                resume_thread_id=None,
            )

            result = runner.run(invocation)

            self.assertEqual(builder.resume_ids, [None])
            self.assertIsNone(result.thread_id)


if __name__ == "__main__":
    unittest.main()
