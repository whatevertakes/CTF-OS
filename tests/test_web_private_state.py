from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.sandbox.types import ChallengeScope, CommandSpec, SandboxError
from ctf_os.sandbox.web_private import (
    PRIVATE_WEB_SESSION_CONTAINER_ROOT,
    PRIVATE_WEB_SESSION_ROOT_ENV,
    PRIVATE_WEB_TIMELINE_CONTAINER_ROOT,
    PRIVATE_WEB_TIMELINE_ROOT_ENV,
    WebPrivateStateError,
    prepare_web_session_command,
    redact_private_timeline,
    redact_public_artifacts,
    redact_value,
    resolve_private_web_mounts,
    resolve_private_web_root,
    snapshot_cookie_values,
    snapshot_all_cookie_values,
    snapshot_run_ids,
)


def _run_result(*, secret: str = "") -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "run_result",
        "run_id": "run-00000001",
        "status": "completed",
        "exit_code": 0,
        "timed_out": False,
        "duration_ms": 1,
        "stdout_summary": f"response {secret}",
        "stderr_summary": "",
        "stdout_bytes": len(f"response {secret}".encode()),
        "stderr_bytes": 0,
        "stdout_path": "/work/.ctf/runs/run-00000001/stdout.log",
        "stderr_path": "/work/.ctf/runs/run-00000001/stderr.log",
    }


class WebPrivateStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        state_root = self.root / ".ctfos"
        state_root.mkdir(mode=0o700)
        os.chmod(state_root, 0o700)
        self.challenge = (
            self.root / "incoming" / "contest" / "web" / "challenge"
        )
        self.challenge.mkdir(parents=True)
        self.challenge_state = (
            state_root
            / "contests"
            / "contest"
            / "challenges"
            / "web"
            / "challenge"
        )
        self.runtime = self.challenge_state / "runtime"
        self.runtime.mkdir(parents=True)
        self.work = self.challenge_state / "runs" / "model-1" / "workspace"
        self.work.mkdir(parents=True)
        self.scope = ChallengeScope(
            "challenge",
            self.challenge,
            self.work,
            contest_id="contest",
            category="web",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_private_root_is_stable_across_managed_workspaces(self) -> None:
        first = resolve_private_web_root(self.scope)
        other_work = (
            self.challenge_state / "runtime" / "staging" / "cycle-2" / "work"
        )
        second_scope = ChallengeScope(
            "challenge",
            self.challenge,
            other_work,
            contest_id="contest",
            category="web",
        )
        second = resolve_private_web_root(second_scope)
        self.assertEqual(first, second)
        self.assertNotIn(first, (self.work, other_work))
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)

    def test_only_direct_trusted_helper_gets_private_session(self) -> None:
        prepared = prepare_web_session_command(
            category="web",
            argv=("ctf-browser", "https://target.test/", "--session", "user"),
            environment={},
        )
        assert prepared is not None
        self.assertEqual(prepared.argv[0], "/opt/venvs/pw/bin/python")
        self.assertEqual(
            prepared.argv[1],
            "/opt/ctf-templates/web/browser.py",
        )
        self.assertEqual(prepared.session_name, "user")
        self.assertIsNotNone(
            prepare_web_session_command(
                category="web",
                argv=(
                    "ctf-browser",
                    "https://target.test/",
                    "--session",
                    "user",
                ),
                environment={"CTF_WRAP_FLAG_PATTERNS_JSON": '["flag"]'},
            )
        )
        with self.assertRaises(WebPrivateStateError):
            prepare_web_session_command(
                category="web",
                argv=(
                    "ctf-browser",
                    "https://target.test/",
                    "--session",
                    "user",
                ),
                environment={"PATH": "/work"},
            )
        self.assertIsNone(
            prepare_web_session_command(
                category="web",
                argv=(
                    "bash",
                    "-c",
                    "ctf-browser https://target.test --session admin",
                ),
                environment={},
            )
        )
        request = prepare_web_session_command(
            category="web",
            argv=(
                "/opt/ctf-templates/web/request.py",
                "https://target.test/",
                "--session",
                "attacker",
                "--data-file",
                "/challenge/body.bin",
            ),
            environment={},
        )
        assert request is not None
        self.assertEqual(request.argv[0], "/opt/venvs/main/bin/python")
        self.assertEqual(
            request.argv[1],
            "/opt/ctf-templates/web/request.py",
        )
        with self.assertRaises(WebPrivateStateError):
            prepare_web_session_command(
                category="web",
                argv=(
                    "/opt/ctf-templates/web/browser.py",
                    "https://target.test/",
                    "--session",
                    "admin",
                    "--screenshot",
                ),
                environment={},
            )
        with self.assertRaises(WebPrivateStateError):
            prepare_web_session_command(
                category="web",
                argv=(
                    "/opt/ctf-templates/web/request.py",
                    "https://target.test/",
                    "--session",
                    "attacker",
                    "--data-file",
                    "/run/ctfos-web-session/sessions/admin/cookies.json",
                ),
                environment={},
            )
        with self.assertRaises(WebPrivateStateError):
            prepare_web_session_command(
                category="web",
                argv=("true",),
                environment={PRIVATE_WEB_SESSION_ROOT_ENV: "/work"},
            )

    def test_cookie_snapshot_and_public_redaction(self) -> None:
        jar_root, timeline_root = resolve_private_web_mounts(
            self.scope,
            "attacker",
        )
        jar = jar_root / "cookies.json"
        jar.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "session": "attacker",
                    "cookies": [{"value": 'secret-"quoted"'}],
                }
            ),
            encoding="utf-8",
        )
        os.chmod(jar, 0o600)
        secrets = snapshot_cookie_values(jar_root, "attacker")
        self.assertEqual(secrets, ('secret-"quoted"',))
        self.assertEqual(
            snapshot_all_cookie_values(resolve_private_web_root(self.scope)),
            secrets,
        )
        (timeline_root / "timeline.json").write_text(
            'poison secret-"quoted"',
            encoding="utf-8",
        )
        os.chmod(timeline_root / "timeline.json", 0o600)
        redact_private_timeline(timeline_root, secrets)
        self.assertNotIn(
            "secret",
            (timeline_root / "timeline.json").read_text(),
        )

        web = self.work / "web"
        web.mkdir()
        (web / "body.txt").write_text(
            'reflected secret-"quoted"', encoding="utf-8"
        )
        run = self.work / ".ctf" / "runs" / "run-00000001"
        run.mkdir(parents=True)
        (run / "stdout.log").write_text(
            'json secret-\\"quoted\\"', encoding="utf-8"
        )
        redact_public_artifacts(
            self.work,
            previous_run_ids=frozenset(),
            secrets=secrets,
        )
        self.assertNotIn("secret", (web / "body.txt").read_text())
        self.assertNotIn("secret", (run / "stdout.log").read_text())
        self.assertNotIn(
            "secret",
            str(redact_value({"summary": "secret-\"quoted\""}, secrets)),
        )

    def test_backend_mounts_only_for_typed_helper_and_scrubs_result(self) -> None:
        secret = "server-reflected-cookie"
        observed_argv: list[str] = []

        def runner(
            argv: list[str],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            observed_argv[:] = argv
            jar_root, _timeline_root = resolve_private_web_mounts(
                self.scope,
                "attacker",
            )
            jar = jar_root / "cookies.json"
            jar.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "session": "attacker",
                        "cookies": [{"value": secret}],
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(jar, 0o600)
            web = self.work / "web"
            web.mkdir(exist_ok=True)
            (web / "body.txt").write_text(secret, encoding="utf-8")
            run = self.work / ".ctf" / "runs" / "run-00000001"
            run.mkdir(parents=True)
            (run / "stdout.log").write_text(secret, encoding="utf-8")
            (run / "stderr.log").write_text("", encoding="utf-8")
            (run / "result.json").write_text(
                json.dumps(_run_result(secret=secret)),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(_run_result(secret=secret)),
                "",
            )

        backend = DockerSandboxBackend(self.scope, runner=runner)
        result = backend.run(
            CommandSpec(
                (
                    "/opt/ctf-templates/web/request.py",
                    "https://target.test/",
                    "--session",
                    "attacker",
                ),
                environment={"CTF_WRAP_FLAG_PATTERNS_JSON": '["flag"]'},
            )
        )
        joined = "\0".join(observed_argv)
        self.assertIn(PRIVATE_WEB_SESSION_CONTAINER_ROOT, joined)
        self.assertIn(PRIVATE_WEB_TIMELINE_CONTAINER_ROOT, joined)
        self.assertIn(
            (
                f"{PRIVATE_WEB_SESSION_ROOT_ENV}="
                f"{PRIVATE_WEB_SESSION_CONTAINER_ROOT}"
            ),
            observed_argv,
        )
        self.assertIn(
            (
                f"{PRIVATE_WEB_TIMELINE_ROOT_ENV}="
                f"{PRIVATE_WEB_TIMELINE_CONTAINER_ROOT}"
            ),
            observed_argv,
        )
        self.assertNotIn(secret, result.stdout_summary)
        self.assertNotIn(secret, (self.work / "web" / "body.txt").read_text())
        self.assertNotIn(
            secret,
            (
                self.work
                / ".ctf"
                / "runs"
                / "run-00000001"
                / "stdout.log"
            ).read_text(),
        )

    def test_clean_proof_cannot_reuse_private_identity(self) -> None:
        backend = DockerSandboxBackend(
            self.scope,
            runner=lambda *args, **kwargs: self.fail(
                "runner must not be reached"
            ),
        )
        with self.assertRaisesRegex(SandboxError, "unavailable in a clean proof"):
            backend.run_clean_proof(
                CommandSpec(
                    (
                        "ctf-browser",
                        "https://target.test/",
                        "--session",
                        "admin",
                    )
                )
            )

    def test_failed_post_run_cookie_audit_discards_public_outputs(self) -> None:
        leaked = self.work / "web" / "body.txt"

        def runner(
            argv: list[str],
            **_kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            jar_root, _timeline_root = resolve_private_web_mounts(
                self.scope,
                "attacker",
            )
            jar = jar_root / "cookies.json"
            jar.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "session": "attacker",
                        "cookies": [{"value": "new-unaudited-secret"}],
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(jar, 0o644)
            leaked.parent.mkdir(exist_ok=True)
            leaked.write_text("new-unaudited-secret", encoding="utf-8")
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(_run_result()),
                "",
            )

        backend = DockerSandboxBackend(self.scope, runner=runner)
        with self.assertRaisesRegex(SandboxError, "cookie jar"):
            backend.run(
                CommandSpec(
                    (
                        "/opt/ctf-templates/web/request.py",
                        "https://target.test/",
                        "--session",
                        "attacker",
                    )
                )
            )
        self.assertFalse(leaked.exists())

    def test_snapshot_run_ids_ignores_noncanonical_names(self) -> None:
        runs = self.work / ".ctf" / "runs"
        (runs / "run-00000001").mkdir(parents=True)
        (runs / "not-a-run").mkdir()
        self.assertEqual(snapshot_run_ids(self.work), {"run-00000001"})


if __name__ == "__main__":
    unittest.main()
