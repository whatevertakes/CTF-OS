from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os import cli
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.engine.rev_acceptance import (
    REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
    RevAcceptanceContractError,
    RevAcceptanceOperatorSpec,
    build_rev_acceptance_plan,
    canonical_json_bytes,
)
from ctf_os.engine.rev_acceptance_state import (
    validate_rev_acceptance_state_graph,
)
from ctf_os.models import (
    ChallengeIdentity,
    FlagCandidate,
    ModelValidationError,
    RunOrigin,
)
from ctf_os.sandbox import SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import (
    RevInventorySandbox,
    _elf64_image,
    _rev_inventory_payload,
)


ACCEPTED_INPUT = b"OPEN-SESAME\n"
ACCEPTED_OUTPUT = b"REV_OK_93D1\n"
REJECTED_OUTPUT = b"REV_NO_72A4\n"


class RevAcceptanceSandbox(RevInventorySandbox):
    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        del input_locators
        self.proof_specs.append(spec)
        self.proof_calls += 1
        if len(proof_inputs) != 1:
            raise AssertionError("Rev acceptance requires one proof input")
        item = proof_inputs[0]
        payload = (self.work / item.source_locator).read_bytes()
        if (
            hashlib.sha256(payload).hexdigest() != item.sha256
            or len(payload) != item.size_bytes
            or item.destination_locator != "oracle/accepted-input.bin"
        ):
            raise AssertionError("proof input binding changed")
        accepted = payload == ACCEPTED_INPUT
        relative = Path("proof") / f"clean-{self.proof_calls}"
        directory = self.work / relative
        directory.mkdir(parents=True)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_bytes(
            ACCEPTED_OUTPUT if accepted else REJECTED_OUTPUT
        )
        stderr.write_bytes(b"")
        stdout_size = stdout.stat().st_size
        return SandboxResult(
            f"rev-proof-{self.proof_calls}",
            "completed" if accepted else "failed",
            0 if accepted else 7,
            False,
            5,
            stdout.read_text(encoding="ascii").strip(),
            "",
            stdout_size,
            0,
            f"/work/{relative.as_posix()}/stdout.log",
            f"/work/{relative.as_posix()}/stderr.log",
            stdout_stored_bytes=stdout_size,
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
        )


class InterruptingRevAcceptanceSandbox(RevAcceptanceSandbox):
    def __init__(self, work: Path, payload: bytes) -> None:
        super().__init__(work, payload)
        self.proof_calls = 100

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        if self.proof_calls == 101:
            raise RuntimeError("injected second-attempt interruption")
        return super().run_clean_proof(
            spec,
            input_locators=input_locators,
            proof_inputs=proof_inputs,
        )


def _expectation(
    *,
    exit_code: int,
    payload: bytes,
) -> dict[str, object]:
    return {
        "exit_code": exit_code,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_size_bytes": 0,
        "stdout_sha256": hashlib.sha256(payload).hexdigest(),
        "stdout_size_bytes": len(payload),
    }


def _spec() -> dict[str, object]:
    return {
        "accepted": _expectation(
            exit_code=0,
            payload=ACCEPTED_OUTPUT,
        ),
        "accepted_input_locator": "accepted-input.bin",
        "controls": [
            {
                "expectation": _expectation(
                    exit_code=7,
                    payload=REJECTED_OUTPUT,
                ),
                "mutation_id": mutation_id,
            }
            for mutation_id in (
                "xor-first-01",
                "xor-last-80",
                "truncate-last",
            )
        ],
        "protocol": REV_ACCEPTANCE_OPERATOR_SPEC_PROTOCOL,
        "schema_version": 1,
        "source_locator": "challenge.bin",
    }


class RevAcceptanceContractTests(unittest.TestCase):
    def test_plan_is_fixed_three_positive_three_distinct_controls(self):
        plan = build_rev_acceptance_plan(ACCEPTED_INPUT)
        self.assertEqual(len(plan), 6)
        self.assertEqual(
            [item.phase for item in plan],
            ["positive"] * 3 + ["control"] * 3,
        )
        self.assertEqual(
            [item.payload for item in plan[:3]],
            [ACCEPTED_INPUT] * 3,
        )
        self.assertEqual(len({item.payload for item in plan[3:]}), 3)
        self.assertNotIn(ACCEPTED_INPUT, [item.payload for item in plan[3:]])

    def test_operator_spec_rejects_unknown_fields_and_control_reorder(self):
        unknown = _spec()
        unknown["verdict"] = "accept"
        with self.assertRaises(RevAcceptanceContractError):
            RevAcceptanceOperatorSpec.from_mapping(unknown)

        reordered = _spec()
        reordered["controls"] = list(
            reversed(reordered["controls"])
        )
        with self.assertRaises(RevAcceptanceContractError):
            RevAcceptanceOperatorSpec.from_mapping(reordered)

        non_rejecting = _spec()
        non_rejecting["controls"][0]["expectation"] = copy.deepcopy(
            non_rejecting["accepted"]
        )
        with self.assertRaises(RevAcceptanceContractError):
            RevAcceptanceOperatorSpec.from_mapping(non_rejecting)


class RevAcceptanceCLITests(unittest.TestCase):
    def test_parser_and_cli_route_only_explicit_operator_inputs(self):
        parser = cli.build_parser()
        arguments = [
            "rev-prove-accept",
            "EVENT",
            "rev",
            "keycheck",
            "--spec",
            "oracle.json",
            "--timeout",
            "321",
        ]
        parsed = parser.parse_args(arguments)
        self.assertEqual(parsed.command, "rev-prove-accept")
        self.assertEqual(parsed.spec, "oracle.json")
        self.assertEqual(parsed.timeout, 321)

        result = {
            "authorities": {
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "challenge_status_transition_authorized": False,
                "flag_proven": False,
            },
            "observations": [{}, {}, {}, {}, {}, {}],
            "passed": True,
            "reason_codes": [],
        }
        state = mock.Mock(revision=17)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            ChallengeEngine,
            "prove_rev_accepted_input",
            autospec=True,
            return_value=(state, result),
        ) as prove, redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.main(arguments, root=Path(temporary))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        prove.assert_called_once()
        _engine, identity = prove.call_args.args
        self.assertEqual(
            identity,
            ChallengeIdentity("EVENT", "rev", "keycheck"),
        )
        self.assertEqual(
            prove.call_args.kwargs,
            {
                "operator_spec_locator": "oracle.json",
                "timeout_seconds": 321,
            },
        )
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["authorities"], result["authorities"])
        self.assertEqual(output["passed"], True)
        self.assertEqual(output["run_count"], 6)
        self.assertEqual(output["state_revision"], 17)


class RevAcceptanceStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Rev State",
            "rev",
            "accepted-input",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        source = _elf64_image(2) + b"rev-acceptance-test"
        (incoming / "challenge.bin").write_bytes(source)
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest="sha256:" + ("7" * 64),
                command_timeout_s=30,
            ),
        )
        payload = _rev_inventory_payload(source)
        self.engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=lambda state, work, policy: (
                RevAcceptanceSandbox(work, payload)
            ),
        )
        state = self.engine.add_challenge(
            self.identity,
            prompt="test",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        state = self.engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )
        self.before_status = state.status
        workspace = self.engine._workspace(state)
        (workspace / "accepted-input.bin").write_bytes(ACCEPTED_INPUT)
        (workspace / "spec.json").write_bytes(
            canonical_json_bytes(_spec())
        )
        self.state, self.evaluation = (
            self.engine.prove_rev_accepted_input(
                self.identity,
                operator_spec_locator="spec.json",
                timeout_seconds=10,
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _experiment(self, state):
        return next(
            item
            for item in state.experiments
            if isinstance(item.result, dict)
            and "rev_acceptance_evidence" in item.result
        )

    def test_candidate_free_graph_round_trips(self) -> None:
        self.assertTrue(self.evaluation["passed"])
        self.assertEqual(len(self.evaluation["observations"]), 6)
        self.assertEqual(self.state.status, self.before_status)
        self.assertEqual(self.state.candidates, [])
        self.assertEqual(self.state.submissions, [])
        self.assertEqual(
            self.evaluation["authorities"],
            {
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "challenge_status_transition_authorized": False,
                "flag_proven": False,
            },
        )
        validate_rev_acceptance_state_graph(self.state)
        self.state.validate()
        round_trip = type(self.state).from_dict(self.state.to_dict())
        round_trip.validate()

        later_configuration = copy.deepcopy(self.state)
        later_configuration.configuration_epoch += 1
        later_configuration.validate()

    def test_operator_inventory_origin_is_scoped_to_public_gate(self) -> None:
        inventory_run = next(
            item
            for item in self.state.runs
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        self.assertIs(inventory_run.origin, RunOrigin.OPERATOR_TOOL)
        with self.assertRaises(EngineError):
            self.engine._resolve_rev_stdin_inventory_binding(self.state)
        binding, _experiment, _source = (
            self.engine._resolve_rev_stdin_inventory_binding(
                self.state,
                allowed_run_origins=frozenset(
                    {
                        RunOrigin.MANAGED_TOOL,
                        RunOrigin.OPERATOR_TOOL,
                    }
                ),
            )
        )
        self.assertEqual(
            binding.inventory_run_id,
            inventory_run.id,
        )

    def test_interruption_removes_uncommitted_artifacts_and_runs(self):
        paths = self.engine.store.challenge_paths(self.identity)

        def files_under(path: Path) -> set[str]:
            return {
                item.relative_to(path).as_posix()
                for item in path.rglob("*")
                if item.is_file()
            }

        before_state = self.engine.store.load(self.identity)
        acceptance_artifacts = paths.artifacts / "rev-acceptance"
        before_files = files_under(acceptance_artifacts)
        before_run_directories = {
            item.name for item in paths.runs.iterdir() if item.is_dir()
        }
        payload = _rev_inventory_payload(
            _elf64_image(2) + b"rev-acceptance-test"
        )
        self.engine._sandbox_factory = (
            lambda state, work, policy: (
                InterruptingRevAcceptanceSandbox(work, payload)
            )
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "injected second-attempt interruption",
        ):
            self.engine.prove_rev_accepted_input(
                self.identity,
                operator_spec_locator="spec.json",
                timeout_seconds=10,
            )

        after_state = self.engine.store.load(self.identity)
        self.assertEqual(after_state.revision, before_state.revision)
        self.assertEqual(
            files_under(acceptance_artifacts),
            before_files,
        )
        self.assertEqual(
            {
                item.name
                for item in paths.runs.iterdir()
                if item.is_dir()
            },
            before_run_directories,
        )

    def test_hash_receipt_fact_and_authority_tampering_fail_closed(self):
        mutations = []

        def artifact_hash(state):
            experiment = self._experiment(state)
            artifact = next(
                item
                for item in state.artifacts
                if item.id == experiment.artifact_ids[2]
            )
            artifact.sha256 = "0" * 64

        mutations.append(artifact_hash)

        def receipt_run(state):
            experiment = self._experiment(state)
            receipt = next(
                item
                for item in state.receipts
                if item.id == experiment.evidence_receipt_ids[0]
            )
            receipt.run_id = experiment.evidence_run_ids[1]

        mutations.append(receipt_run)

        def fact_artifact(state):
            experiment = self._experiment(state)
            fact = next(
                item
                for item in state.facts
                if item.id == experiment.evidence_fact_ids[0]
            )
            fact.artifact_id = experiment.artifact_ids[0]

        mutations.append(fact_artifact)

        def authority(state):
            experiment = self._experiment(state)
            experiment.result["rev_acceptance_evidence"][
                "authorities"
            ]["candidate_authorized"] = True

        mutations.append(authority)

        def network_policy(state):
            experiment = self._experiment(state)
            experiment.result["rev_acceptance_evidence"]["evaluation"][
                "observations"
            ][0]["network"] = "target"

        mutations.append(network_policy)

        def candidate_promotion(state):
            experiment = self._experiment(state)
            state.candidates.append(
                FlagCandidate(
                    id="C-forged",
                    value="not-a-flag",
                    source_run_id=experiment.evidence_run_ids[0],
                )
            )

        mutations.append(candidate_promotion)

        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                changed = copy.deepcopy(self.state)
                mutate(changed)
                with self.assertRaises((ModelValidationError, ValueError)):
                    changed.validate()

    def test_raw_input_and_output_do_not_enter_state(self) -> None:
        payload = json.dumps(
            self.state.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self.assertNotIn(ACCEPTED_INPUT.rstrip(), payload)
        self.assertNotIn(ACCEPTED_OUTPUT.rstrip(), payload)
        self.assertNotIn(REJECTED_OUTPUT.rstrip(), payload)


if __name__ == "__main__":
    unittest.main()
