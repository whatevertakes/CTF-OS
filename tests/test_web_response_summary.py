from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.web_response_summary import (
    WEB_RESPONSE_SUMMARY_PREFIX,
    evaluate_web_response_stdout,
    parse_web_response_summaries,
)
from ctf_os.models import (
    ChallengeIdentity,
    ExperimentStatus,
    ReceiptOutcome,
    RunStatus,
)
from ctf_os.sandbox import SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import canonical_json_record
from tests.test_engine import FakeSandbox


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WEB_TEMPLATE_ROOT = REPOSITORY_ROOT / "ctf-os-image" / "templates" / "web"
IMAGE_DIGEST = "sha256:" + "e" * 64


def _load_request_helper() -> object:
    previous = {
        name: sys.modules.get(name)
        for name in ("safe_output", "session_state")
    }
    sys.path.insert(0, str(WEB_TEMPLATE_ROOT))
    try:
        for name in previous:
            sys.modules.pop(name, None)
        spec = importlib.util.spec_from_file_location(
            "ctfos_web_request_summary_under_test",
            WEB_TEMPLATE_ROOT / "request.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(WEB_TEMPLATE_ROOT))
        for name, module in previous.items():
            sys.modules.pop(name, None)
            if module is not None:
                sys.modules[name] = module


REQUEST_HELPER = _load_request_helper()


def _summary_line(record: dict[str, object]) -> bytes:
    return WEB_RESPONSE_SUMMARY_PREFIX + canonical_json_record(record).encode(
        "ascii"
    )


def _record(*, marker: str = "harmless-marker") -> dict[str, object]:
    return REQUEST_HELPER._response_summary(
        method="GET",
        url="https://target.test/?probe=redacted",
        request_body=None,
        status=200,
        raw_body=("prefix " + marker + " suffix").encode("utf-8"),
        truncated=False,
        observations=[marker],
    )


class _WebSummarySandbox(FakeSandbox):
    def __init__(self, work: Path, payload: bytes) -> None:
        super().__init__(work)
        self.payload = payload

    def run(self, spec):
        self.specs.append(spec)
        raw = self.work / "raw"
        raw.mkdir(exist_ok=True)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        stdout.write_bytes(self.payload)
        stderr.write_bytes(b"")
        return SandboxResult(
            "tool-web-summary",
            "completed",
            0,
            False,
            5,
            self.payload.decode("utf-8"),
            "",
            len(self.payload),
            0,
            "/work/raw/stdout.log",
            "/work/raw/stderr.log",
            stdout_stored_bytes=len(self.payload),
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
        )


class WebResponseSummaryTests(unittest.TestCase):
    def test_helper_summary_is_value_free_and_parser_accepts_it(self) -> None:
        marker = "marker-that-must-not-be-printed"
        body_secret = "body-secret-that-must-not-be-printed"
        record = REQUEST_HELPER._response_summary(
            method="GET",
            url="https://target.test/",
            request_body=None,
            status=200,
            raw_body=f"{marker}:{body_secret}".encode("utf-8"),
            truncated=False,
            observations=[marker],
        )
        line = _summary_line(record)

        self.assertNotIn(marker.encode("utf-8"), line)
        self.assertNotIn(body_secret.encode("utf-8"), line)
        parsed = parse_web_response_summaries(line + b"\nmetadata follows\n")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["status"], 200)
        self.assertEqual(parsed[0]["saved_bytes"], len(marker) + len(body_secret) + 1)
        self.assertEqual(
            parsed[0]["observations"][0],
            {
                "count_capped": False,
                "match_count": 1,
                "needle_sha256": hashlib.sha256(marker.encode()).hexdigest(),
                "present": True,
            },
        )

    def test_parser_preserves_order_for_multiple_helper_invocations(self) -> None:
        first = _record(marker="first-marker")
        second = _record(marker="second-marker")
        payload = b"\n".join(
            (
                _summary_line(first),
                b'{"ordinary":"helper metadata"}',
                _summary_line(second),
            )
        )

        parsed = parse_web_response_summaries(payload)

        self.assertEqual(
            [item["body_sha256"] for item in parsed],
            [first["body_sha256"], second["body_sha256"]],
        )

    def test_noncanonical_or_missing_record_is_rejected(self) -> None:
        record = _record()
        noncanonical = (
            WEB_RESPONSE_SUMMARY_PREFIX
            + json.dumps(record, sort_keys=True).encode("utf-8")
        )
        with self.assertRaisesRegex(ValueError, "canonical"):
            parse_web_response_summaries(noncanonical)
        with self.assertRaisesRegex(ValueError, "no response summary"):
            parse_web_response_summaries(b'{"ok":true}\n')

    def test_incomplete_stdout_fails_closed_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "stdout.log"
            payload = _summary_line(_record()) + b"\n"
            path.write_bytes(payload)
            os.chmod(path, 0o400)
            evaluation = evaluate_web_response_stdout(
                root,
                "stdout.log",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                expected_size=len(payload),
                coverage="retained_prefix_only",
            )

        self.assertFalse(evaluation["valid"])
        self.assertEqual(evaluation["reason_code"], "stdout_incomplete")


class ManagedRemoteWebSummaryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity("Web Summary", "web", "one")
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "source.txt").write_text("bounded source", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _execute(self, payload: bytes):
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(config.runtime, image_digest=IMAGE_DIGEST),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=lambda state, work, policy: _WebSummarySandbox(
                work,
                payload,
            ),
        )
        engine.add_challenge(
            self.identity,
            prompt="run one bounded remote Web observation",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = engine.add_network_target(
            self.identity,
            "https://target.test:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="durable response summary",
            keep_if="the marker is present",
            drop_if="the marker is absent",
            network_target=target.endpoint,
        )

        def bind_managed_contract(current):
            experiment = next(
                item
                for item in current.experiments
                if item.id == experiment_id
            )
            experiment.extra["managed_contract_version"] = 2

        engine.store.update(self.identity, bind_managed_contract)
        return engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        ), experiment_id

    def test_exit_zero_without_summary_is_failed_but_stdout_is_preserved(self) -> None:
        state, experiment_id = self._execute(b'{"ok":true}\n')
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )

        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(
            experiment.result["web_response_summary"]["reason_code"],
            "record_missing",
        )
        self.assertEqual(state.runs[-1].status, RunStatus.FAILED)
        self.assertEqual(state.receipts[-1].outcome, ReceiptOutcome.FAILED)
        self.assertEqual(len(experiment.artifact_ids), 2)

    def test_valid_summary_is_durable_in_result_and_receipt(self) -> None:
        marker = "harmless-marker"
        record = _record(marker=marker)
        payload = _summary_line(record) + b"\n"
        state, experiment_id = self._execute(payload)
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )

        self.assertIs(experiment.status, ExperimentStatus.COMPLETED)
        self.assertTrue(experiment.result["web_response_summary"]["valid"])
        self.assertEqual(state.runs[-1].status, RunStatus.COMPLETED)
        self.assertEqual(state.receipts[-1].outcome, ReceiptOutcome.SUCCEEDED)
        self.assertEqual(
            state.receipts[-1].extra["web_response_summary"]["record_count"],
            1,
        )
        state_path = (
            self.root
            / ".ctfos"
            / "contests"
            / self.identity.contest_id
            / "challenges"
            / self.identity.category
            / self.identity.challenge_id
            / "state.json"
        )
        context = build_context_pack(
            state,
            get_adapter("web"),
            state_path=state_path,
        ).text
        self.assertIn(str(record["body_sha256"]), context)
        self.assertIn(
            str(record["observations"][0]["needle_sha256"]),
            context,
        )
        self.assertNotIn(marker, context)


if __name__ == "__main__":
    unittest.main()
