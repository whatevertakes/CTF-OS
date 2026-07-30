from __future__ import annotations

import sys
import unittest
from pathlib import Path

from ctf_os.codex.commands import (
    LIVE_FULL_SCAFFOLD,
    LIVE_THIN_SCAFFOLD,
    LiveCommandBuilder,
    LiveSession,
)
from ctf_os.codex.contracts import ModelCatalog, ReasoningEffort, Role


class ThinLiveScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = LiveCommandBuilder(
            models=ModelCatalog(sol="frontier-model"),
            mcp_executable=sys.executable,
        )

    def test_default_full_scaffold_is_unchanged(self) -> None:
        session = LiveSession("full", Path("/challenge"), "solve")
        self.assertEqual(session.scaffold, LIVE_FULL_SCAFFOLD)
        self.assertEqual(
            session.logical_worker_roles,
            (Role.RECON, Role.SPECIALIST, Role.FALSIFIER),
        )
        built = self.builder.start(session)
        self.assertIn("features.multi_agent=true", built.argv)
        self.assertIn("agents.enabled=true", built.argv)
        self.assertIn(
            "agents.max_concurrent_threads_per_session=4",
            built.argv,
        )

    def test_scaffolds_reject_role_relabeling(self) -> None:
        with self.assertRaisesRegex(ValueError, "thin.*roles"):
            LiveSession(
                "thin-bad",
                Path("/challenge"),
                "solve",
                scaffold=LIVE_THIN_SCAFFOLD,
            )
        with self.assertRaisesRegex(ValueError, "full.*role"):
            LiveSession(
                "full-bad",
                Path("/challenge"),
                "solve",
                logical_worker_roles=(),
            )

    def test_thin_is_one_model_with_same_challenge_mcp_surface(self) -> None:
        full = self.builder.start(
            LiveSession("full", Path("/one"), "solve")
        )
        thin = self.builder.start(
            LiveSession(
                "thin",
                Path("/two"),
                "solve",
                logical_worker_roles=(),
                scaffold=LIVE_THIN_SCAFFOLD,
            )
        )
        self.assertIn("features.multi_agent=false", thin.argv)
        self.assertIn("agents.enabled=false", thin.argv)
        self.assertIn(
            "agents.max_concurrent_threads_per_session=1",
            thin.argv,
        )
        self.assertIn("sole frontier agent", thin.argv[-1])
        self.assertIn("Do not create", thin.argv[-1])
        self.assertNotIn("Maintain these logical worker roles", thin.argv[-1])
        full_tools = next(
            value
            for value in full.argv
            if value.startswith("mcp_servers.ctfos_live.enabled_tools=")
        )
        thin_tools = next(
            value
            for value in thin.argv
            if value.startswith("mcp_servers.ctfos_live.enabled_tools=")
        )
        self.assertEqual(full_tools, thin_tools)

    def test_command_contract_ignores_prompt_and_paths_but_binds_scaffold(self) -> None:
        thin_one = LiveSession(
            "thin-one",
            Path("/one"),
            "first prompt",
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        thin_two = LiveSession(
            "thin-two",
            Path("/two"),
            "different prompt",
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        full = LiveSession("full", Path("/one"), "first prompt")
        self.assertEqual(
            self.builder.command_contract_sha256(thin_one),
            self.builder.command_contract_sha256(thin_two),
        )
        self.assertNotEqual(
            self.builder.command_contract_sha256(thin_one),
            self.builder.command_contract_sha256(full),
        )
        stronger = LiveSession(
            "thin-three",
            Path("/one"),
            "first prompt",
            model_id="different-model",
            reasoning_effort=ReasoningEffort.XHIGH,
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        self.assertNotEqual(
            self.builder.command_contract_sha256(thin_one),
            self.builder.command_contract_sha256(stronger),
        )

    def test_resume_keeps_thin_isolation(self) -> None:
        session = LiveSession(
            "thin",
            Path("/challenge"),
            "solve",
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        resumed = self.builder.resume(session, "thread-123")
        self.assertIn("features.multi_agent=false", resumed.argv)
        self.assertIn("agents.enabled=false", resumed.argv)
        self.assertIn(
            "agents.max_concurrent_threads_per_session=1",
            resumed.argv,
        )
        self.assertNotIn("Maintain these logical worker roles", resumed.argv[-1])


if __name__ == "__main__":
    unittest.main()
