from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_os.codex.events import EventAccumulator, FlagDetector
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity


class FlagScannerCanonicalStateTests(unittest.TestCase):
    def test_code_noise_cannot_spend_quota_or_pollute_canonical_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity = ChallengeIdentity(
                "Domestic CTF",
                "web",
                "scanner precision",
            )
            engine = ChallengeEngine(Path(temporary))
            engine.add_challenge(identity, prompt="solve")
            detector = FlagDetector(
                candidate_limit=4,
                suppress_generic_code_noise=True,
            )
            accumulator = EventAccumulator(
                detector=detector,
                on_flag=lambda candidate: engine.record_candidate(
                    identity,
                    candidate.value,
                    print_immediately=False,
                ),
            )

            accumulator.feed(
                json.dumps(
                    {
                        "type": "item.completed",
                        "text": (
                            ".disabled{color:#ccc} "
                            "return{file:!1} "
                            "function{return result=1} "
                            "<script>NYU{alpha:1,beta:2} "
                            "ACSC{file:!1,glob:!1} "
                            "LINECTF{color:red;margin:0} "
                            "'zer0pts{alpha:1,beta:2}'</script>"
                        ),
                    }
                )
            )

            state = engine.store.load(identity)

        self.assertEqual(
            [candidate.value for candidate in state.candidates],
            [
                "NYU{alpha:1,beta:2}",
                "ACSC{file:!1,glob:!1}",
                "LINECTF{color:red;margin:0}",
                "zer0pts{alpha:1,beta:2}",
            ],
        )
        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            [
                "NYU{alpha:1,beta:2}",
                "ACSC{file:!1,glob:!1}",
                "LINECTF{color:red;margin:0}",
                "zer0pts{alpha:1,beta:2}",
            ],
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 3)
        self.assertEqual(detector.suppressed_matches, 3)


if __name__ == "__main__":
    unittest.main()
