from __future__ import annotations

import sys
import unittest
from pathlib import Path

from ctf_os.codex.commands import (
    BuiltCommand,
    LIVE_FULL_SCAFFOLD,
    LIVE_THIN_SCAFFOLD,
    LiveCommandBuilder,
    LiveSession,
)
from ctf_os.codex.contracts import ModelCatalog, ReasoningEffort, Role
from ctf_os.codex.runner import SubprocessExecutor


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

    def test_headless_thin_emits_jsonl_and_usage_bound_contract(self) -> None:
        session = LiveSession(
            "thin",
            Path("/challenge"),
            "solve",
            logical_worker_roles=(),
            scaffold=LIVE_THIN_SCAFFOLD,
        )
        built = self.builder.headless(
            session,
            Path("/run/schema.json"),
            Path("/run/output.json"),
        )
        self.assertEqual(built.argv[:3], ("codex", "exec", "--json"))
        self.assertIn("--output-schema", built.argv)
        self.assertIn("--output-last-message", built.argv)
        self.assertIn("features.multi_agent=false", built.argv)
        self.assertIn("agents.enabled=false", built.argv)
        self.assertEqual(built.argv[-1], "-")
        self.assertIn("sole frontier agent", built.stdin)
        self.assertNotEqual(
            self.builder.command_contract_sha256(session),
            self.builder.command_contract_sha256(
                session,
                headless=True,
            ),
        )
        with self.assertRaisesRegex(ValueError, "thin scaffold"):
            self.builder.headless(
                LiveSession("full", Path("/challenge"), "solve"),
                Path("/run/schema.json"),
                Path("/run/output.json"),
            )

    def test_built_command_passes_scoped_environment_without_repr_leak(
        self,
    ) -> None:
        observed: list[str | bytes] = []
        command = BuiltCommand(
            (
                sys.executable,
                "-c",
                (
                    "import os;"
                    "print(os.environ['CTFOS_TEST_SCOPE'], flush=True)"
                ),
            ),
            "",
            {"CTFOS_TEST_SCOPE": "bound-secret"},
        )
        self.assertNotIn("bound-secret", repr(command))
        outcome = SubprocessExecutor().run(
            command,
            cwd=Path.cwd(),
            timeout=5,
            on_stdout_line=observed.append,
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertIn(b"bound-secret", b"".join(observed))


if __name__ == "__main__":
    unittest.main()
