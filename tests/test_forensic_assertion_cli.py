from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

from ctf_os import cli
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity


class ForensicAssertionCLITests(unittest.TestCase):
    def test_parser_preserves_operator_spec_hypotheses_and_timeout(
        self,
    ) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "forensic-prove",
                "EVENT",
                "forensic",
                "disk-01",
                "--spec",
                "assertions.json",
                "--hypothesis",
                "H-alpha",
                "--hypothesis",
                "H-beta",
                "--timeout",
                "321",
            ]
        )

        self.assertEqual(args.command, "forensic-prove")
        self.assertEqual(args.spec, "assertions.json")
        self.assertEqual(args.hypothesis, ["H-alpha", "H-beta"])
        self.assertEqual(args.timeout, 321)

    def test_cli_routes_only_explicit_identity_and_operator_inputs(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            contest_id="EVENT",
            category="forensic",
            challenge_id="disk-01",
        )
        authorities = {
            "candidate_authorized": False,
            "executed_forensic_assertion_fact_authorized": True,
            "flag_proof_authorized": False,
            "impact_claim_authorized": False,
            "progress_marker_authorized": True,
            "submission_authorized": False,
        }
        result = SimpleNamespace(
            confirmed=True,
            execution_plan_sha256="1" * 64,
            reason_codes=(),
            records=(object(), object()),
            verdict=SimpleNamespace(value="CONFIRMED"),
            to_dict=lambda: {
                "authorities": authorities,
                "semantic_evaluation_sha256": "2" * 64,
            },
        )
        state = SimpleNamespace(revision=17)
        arguments = [
            "forensic-prove",
            identity.contest_id,
            identity.category,
            identity.challenge_id,
            "--spec",
            "assertions.json",
            "--hypothesis",
            "H-alpha",
            "--timeout",
            "321",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(
            ChallengeEngine,
            "prove_forensic_assertion",
            autospec=True,
            return_value=(state, result),
        ) as prove, redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli.main(arguments)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        prove.assert_called_once()
        _engine, routed_identity = prove.call_args.args
        self.assertEqual(routed_identity, identity)
        self.assertEqual(
            prove.call_args.kwargs,
            {
                "operator_spec_locator": "assertions.json",
                "hypothesis_ids": ("H-alpha",),
                "timeout_seconds": 321,
            },
        )
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "authorities": authorities,
                "confirmed": True,
                "execution_plan_sha256": "1" * 64,
                "reason_codes": [],
                "record_count": 2,
                "semantic_evaluation_sha256": "2" * 64,
                "state_revision": 17,
                "verdict": "CONFIRMED",
            },
        )


if __name__ == "__main__":
    unittest.main()
