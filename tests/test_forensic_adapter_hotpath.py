from __future__ import annotations

import shlex
import tempfile
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity, ExperimentStatus


class ForensicAdapterHotPathTests(unittest.TestCase):
    def test_engine_registers_source_bound_evidence_index_seed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = ChallengeIdentity("contest", "forensics", "case")
            engine = ChallengeEngine(root)
            incoming = engine.challenge_input(identity)
            incoming.mkdir(parents=True)
            evidence = incoming / "traffic.pcapng"
            evidence.write_bytes(b"\x0a\x0d\x0d\x0a" + b"capture")

            state = engine.add_challenge(identity, prompt="investigate")
            seed = next(
                experiment
                for experiment in state.experiments
                if experiment.extra.get("adapter_seed") is True
            )

            self.assertIs(seed.status, ExperimentStatus.REGISTERED)
            self.assertEqual(
                shlex.split(seed.command),
                [
                    "/usr/bin/python3",
                    "/opt/ctf-templates/forensic/evidence_index.py",
                    "--root",
                    "/challenge",
                    "--tree",
                    "/work/.ctf/challenge.tree",
                    "--metadata",
                    "/work/.ctf/challenge.json",
                ],
            )
            self.assertTrue(seed.extra["requires_explicit_execution"])
            self.assertEqual(
                state.metadata["adapter_primary_source"],
                "traffic.pcapng",
            )

            primary, plan_sha256, source_binding, plan = (
                engine._managed_adapter_seed_plan(
                    state,
                    get_adapter("forensics"),
                )
            )
            self.assertIsNotNone(primary)
            self.assertEqual(source_binding["path"], "traffic.pcapng")
            self.assertEqual(
                source_binding["manifest_sha256"],
                state.metadata["source_manifest_sha256"],
            )
            self.assertEqual(
                source_binding["adapter_plan_sha256"],
                plan_sha256,
            )
            self.assertEqual(plan[0][2], tuple(shlex.split(seed.command)))
            self.assertFalse(plan[0][0].requires_network)


if __name__ == "__main__":
    unittest.main()
