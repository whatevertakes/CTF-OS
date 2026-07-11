from __future__ import annotations

from io import StringIO
import json
from pathlib import Path
import signal

import pytest

from ctf_os.model_routing import ModelRouter
from ctf_os.solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest


class _CompletedProcess:
    pid = 43210

    def __init__(self) -> None:
        self.stdout = StringIO(
            "analysis line\ntokens used: 1,234\nsession_id: sess-7\nresume-id = resume-7\n"
        )
        self.stderr = StringIO("429 rate limit observed\n")

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0


class _LiveProcess:
    pid = 9988

    def poll(self):
        return None


def _router() -> ModelRouter:
    return ModelRouter.from_mapping(
        {
            "model_profiles": {"default": {"model": "gpt-5.6-terra", "reasoning_effort": "high"}},
            "default_roles": {
                "default": "default", "implementer": "default", "recon": "default",
                "exploit": "default", "source": "default", "fallback": "default",
            },
        }
    )


def test_codex_backend_streams_process_output_and_uses_new_process_group(sterile_staging_factory) -> None:
    received = []
    evidence = StringIO()
    factory_calls = []
    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)

    def factory(*args, **kwargs):
        factory_calls.append((args, kwargs))
        return _CompletedProcess()

    backend = CodexCliBackend(model_router=_router(), process_factory=factory)
    result = backend.run(
        CodexExecRequest(workdir=staging.workdir, prompt="solve", role="implementer", broker_socket=endpoint),
        on_output=received.append,
        evidence_sink=evidence,
    )

    assert factory_calls[0][0][0][:9] == [
        "codex", "exec", "--strict-config", "--ignore-user-config", "--ignore-rules",
        "--ephemeral", "--disable", "hooks", "--skip-git-repo-check",
    ]
    assert "--sandbox" not in factory_calls[0][0][0]
    assert factory_calls[0][1]["start_new_session"] is True
    assert [(record.stream, record.line) for record in received] == [
        ("stdout", "analysis line"),
        ("stdout", "tokens used: 1,234"),
        ("stdout", "session_id: sess-7"),
        ("stdout", "resume-id = resume-7"),
        ("stderr", "429 rate limit observed"),
    ]
    assert "[stderr] 429 rate limit observed" in evidence.getvalue()
    assert result.token_usage == 1234
    assert result.session_id == "sess-7"
    assert result.resume_id == "resume-7"
    # Solver/challenge text can mention a target's HTTP 429; it is not a
    # trusted Codex service failure and must never start a routing cooldown.
    assert not result.rate_limited
    assert result.trusted_failure_kind is None


def test_codex_backend_builds_persistent_resume_argv_with_strict_profile(sterile_staging_factory) -> None:
    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    backend = CodexCliBackend(model_router=_router())

    argv = backend.build_exec_argv(CodexExecRequest(
        workdir=staging.workdir, prompt="issue the next contracts", role="implementer",
        broker_socket=endpoint, resume_id="0195abc0-session_7",
    ))

    assert argv[-3:] == ["resume", "0195abc0-session_7", "issue the next contracts"]
    assert "--ephemeral" not in argv
    assert {"--strict-config", "--ignore-user-config", "--ignore-rules"}.issubset(argv)
    assert 'approval_policy="never"' in argv
    assert 'default_permissions="ctf_os_attempt"' in argv


def test_codex_backend_initial_persistent_session_is_not_ephemeral(sterile_staging_factory) -> None:
    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    argv = CodexCliBackend(model_router=_router()).build_exec_argv(CodexExecRequest(
        workdir=staging.workdir, prompt="create the first plan", role="implementer",
        broker_socket=endpoint, persistent_session=True,
    ))
    assert "resume" not in argv
    assert "--ephemeral" not in argv
    assert argv[-1] == "create the first plan"


@pytest.mark.parametrize("resume_id", ["--last", "", "two sessions", "../../session", "a" * 257])
def test_codex_backend_rejects_unsafe_resume_id(sterile_staging_factory, resume_id: str) -> None:
    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="resume_id"):
        CodexCliBackend(model_router=_router()).build_exec_argv(CodexExecRequest(
            workdir=staging.workdir, prompt="continue", role="implementer",
            broker_socket=endpoint, resume_id=resume_id,
        ))


def test_codex_backend_accepts_only_structured_terminal_rate_limit_events(sterile_staging_factory) -> None:
    class StructuredProcess(_CompletedProcess):
        def __init__(self) -> None:
            self.stdout = StringIO('{"type":"item.completed","item":{"type":"agent_message","text":"[OBSERVATION] target returned HTTP 429"}}\n'
                                   '{"type":"error","error":{"code":"rate_limit_exceeded"}}\n')
            self.stderr = StringIO("")

    staging = sterile_staging_factory()
    endpoint = staging.workdir / ".ctf-os-broker"
    endpoint.mkdir(mode=0o700)
    backend = CodexCliBackend(model_router=_router(), process_factory=lambda *_a, **_k: StructuredProcess())
    result = backend.run(CodexExecRequest(
        workdir=staging.workdir, prompt="solve", role="implementer",
        broker_socket=endpoint, json_events=True,
    ))

    assert result.rate_limited
    assert result.trusted_failure_kind == "rate_limited"
    assert result.failure_provenance == "structured"
    assert result.failure_code == "rate_limit_exceeded"
    assert result.stdout == "[OBSERVATION] target returned HTTP 429"


def test_json_agent_message_is_exposed_as_solver_text_and_thread_is_resumable() -> None:
    lines = (
        json.dumps({"type": "thread.started", "thread_id": "thread-123"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "[FINDING] primitive found\n[TASK_DONE] handoff",
        }}),
    )
    assert CodexCliBackend._assistant_output(lines) == (
        "[FINDING] primitive found\n[TASK_DONE] handoff"
    )
    combined = "\n".join(lines)
    assert CodexCliBackend._parse_session_id(combined) == "thread-123"
    assert CodexCliBackend._parse_resume_id(combined) == "thread-123"


@pytest.mark.parametrize(
    ("event", "kind", "code"),
    [
        ({"type": "error", "message": "localhost provider returned HTTP 429"}, "rate_limited", "rate_limit_exceeded"),
        ({"type": "error", "message": "quota exhausted for this account"}, "rate_limited", "quota_exceeded"),
        ({"type": "turn.failed", "error": {"message": "provider response: HTTP 503"}}, "unavailable", "service_unavailable"),
        ({"type": "turn.failed", "error": {"message": "selected model unavailable"}}, "unavailable", "model_unavailable"),
    ],
)
def test_codex_0144_message_only_terminal_errors_are_trusted(event, kind, code) -> None:
    classified, classified_code = CodexCliBackend._structured_failure(
        (json.dumps(event),), json_events=True,
    )
    assert (classified, classified_code) == (kind, code)


def test_assistant_envelopes_with_service_words_are_never_trusted() -> None:
    events = (
        {"type": "item.completed", "item": {"type": "agent_message", "text": "HTTP 429 rate limit"}},
        {"type": "item.completed", "item": {"type": "command_execution", "aggregated_output": "HTTP 503"}},
    )
    assert CodexCliBackend._structured_failure(
        tuple(json.dumps(event) for event in events), json_events=True,
    ) == (None, None)


def test_codex_backend_kills_only_its_own_private_process_group() -> None:
    calls = []
    backend = CodexCliBackend(
        model_router=_router(),
        killpg=lambda pid, sig: calls.append((pid, sig)),
    )

    backend._kill_process_group(_LiveProcess(), signal.SIGTERM)

    assert calls == [(9988, signal.SIGTERM)]


def test_timeout_cleanup_escalates_from_term_to_kill_for_that_group() -> None:
    calls = []
    backend = CodexCliBackend(
        model_router=_router(),
        killpg=lambda pid, sig: calls.append((pid, sig)),
    )

    backend._terminate_process_group(_LiveProcess(), grace_sec=0)

    assert calls == [(9988, signal.SIGTERM), (9988, signal.SIGKILL)]
