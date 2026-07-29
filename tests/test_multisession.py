from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from collections import defaultdict
from pathlib import Path

from ctf_os.codex import (
    BatchRunner,
    BuiltCommand,
    FileFifoModelCallLimiter,
    ProcessOutcome,
    Role,
)
from ctf_os.engine.challenge import WAVE_ROLES, ChallengeEngine
from ctf_os.models import ChallengeIdentity, RunStatus


def _output_path(command: BuiltCommand) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


def _role_for(command: BuiltCommand) -> Role:
    index = command.argv.index("--output-schema")
    schema = json.loads(Path(command.argv[index + 1]).read_text(encoding="utf-8"))
    title = str(schema["title"])
    return Role(title.removeprefix("CTF-OS ").removesuffix(" result"))


def _payload(role: Role, *, flag: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "role": role.value,
        "status": "ok",
        "summary": f"{role.value} isolated result",
        "observations": [],
        "hypotheses": [],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [],
        "artifacts": [],
        "progress_markers": [],
        "flag_candidates": (
            [
                {
                    "value": flag,
                    "source": "tool_output",
                    "evidence": "structured output",
                }
            ]
            if flag is not None
            else []
        ),
        "decision": None,
        "goal_update": None,
        "refusal": None,
    }


class _TwoSessionExecutor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls: dict[str, list[Role]] = defaultdict(list)

    @staticmethod
    def _session(cwd: Path) -> str:
        text = str(cwd)
        if "session-a" in text:
            return "session-a"
        if "session-b" in text:
            return "session-b"
        raise AssertionError(f"unrecognized isolated workspace: {cwd}")

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del timeout, on_stdout_line
        role = _role_for(command)
        session = self._session(Path(cwd))
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls[session].append(role)
        try:
            # Keep the provider slots occupied long enough for all six logical
            # calls to be created and for four of them to enter the FIFO.
            time.sleep(0.08)
            if session == "session-b" and role is Role.SPECIALIST:
                payload: object = {"schema_version": 1}
            else:
                payload = _payload(
                    role,
                    flag=(
                        "KCTF{session_a_isolated}"
                        if session == "session-a" and role is Role.RECON
                        else None
                    ),
                )
            _output_path(command).write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return ProcessOutcome(0, "", 0.08)
        finally:
            with self._lock:
                self.active -= 1


class MultiSessionIntegrationTests(unittest.TestCase):
    def test_two_challenges_keep_three_roles_and_isolate_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limiter = FileFifoModelCallLimiter(
                root / ".ctfos" / "runtime" / "model-calls.json",
                capacity=2,
                poll_interval=0.005,
            )
            executor = _TwoSessionExecutor()
            engine = ChallengeEngine(
                root,
                batch_runner=BatchRunner(
                    process_executor=executor,
                    limiter=limiter,
                    limiter_wait_timeout=5,
                    max_schema_retries=0,
                ),
            )
            identities = {
                "session-a": ChallengeIdentity(
                    "Domestic CTF",
                    "misc",
                    "session-a",
                ),
                "session-b": ChallengeIdentity(
                    "Domestic CTF",
                    "misc",
                    "session-b",
                ),
            }
            for identity in identities.values():
                engine.add_challenge(identity, prompt="solve the isolated fixture")

            barrier = threading.Barrier(2)
            outcomes: dict[str, object] = {}
            errors: list[BaseException] = []

            def run_session(name: str) -> None:
                try:
                    barrier.wait(timeout=2)
                    outcomes[name] = engine.run_wave(
                        identities[name],
                        "discovery",
                    )
                except BaseException as error:
                    errors.append(error)

            workers = [
                threading.Thread(target=run_session, args=(name,))
                for name in identities
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(5)

            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertFalse(errors, errors)
            self.assertEqual(set(outcomes), set(identities))
            self.assertEqual(executor.max_active, 2)
            for name in identities:
                self.assertCountEqual(
                    executor.calls[name],
                    WAVE_ROLES["discovery"],
                )

            outcome_a = outcomes["session-a"]
            outcome_b = outcomes["session-b"]
            self.assertEqual(len(outcome_a.results), 3)
            self.assertEqual(len(outcome_b.results), 3)
            self.assertTrue(
                all(result.success for result in outcome_a.results),
                [
                    (
                        result.invocation.role.value,
                        result.validation.errors,
                        result.failures,
                    )
                    for result in outcome_a.results
                ],
            )
            self.assertEqual(
                [result.success for result in outcome_b.results],
                [True, False, True],
            )
            self.assertTrue(
                any(
                    result.timing.provider_wait_seconds > 0.02
                    for outcome in (outcome_a, outcome_b)
                    for result in outcome.results
                )
            )

            state_a = engine.store.load(identities["session-a"])
            state_b = engine.store.load(identities["session-b"])
            self.assertEqual(
                [candidate.value for candidate in state_a.candidates],
                ["KCTF{session_a_isolated}"],
            )
            self.assertEqual(state_b.candidates, [])
            self.assertTrue(
                all(run.status is RunStatus.COMPLETED for run in state_a.runs)
            )
            self.assertEqual(
                [run.status for run in state_b.runs].count(RunStatus.INVALID),
                1,
            )
            self.assertTrue(
                {run.id for run in state_a.runs}.isdisjoint(
                    run.id for run in state_b.runs
                )
            )

            snapshot = limiter.snapshot()
            self.assertEqual(snapshot.active, 0)
            self.assertEqual(snapshot.waiting, 0)
            limiter_state = json.loads(
                (
                    root / ".ctfos" / "runtime" / "model-calls.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(limiter_state["holders"], [])
            self.assertEqual(limiter_state["queue"], [])


if __name__ == "__main__":
    unittest.main()
