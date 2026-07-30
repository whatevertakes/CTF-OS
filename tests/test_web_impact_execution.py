from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import replace

from ctf_os.engine.web_impact import (
    WEB_IDENTITY_ROLES,
    WebArtifactCommitment,
    WebImpactReplayObservation,
    WebSourceSinkObservation,
    WebTimelineEvent,
)
from ctf_os.engine.web_impact_execution import (
    WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
    WEB_IMPACT_EXECUTION_PROTOCOL,
    WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES,
    WEB_IMPACT_OPERATOR_SPEC_PROTOCOL,
    WEB_IMPACT_REPLAY_NONCE_MIN_BYTES,
    WebImpactApprovedTarget,
    WebImpactCapturedArtifact,
    WebImpactExecutionPreflightError,
    WebImpactExecutionReceipt,
    WebImpactExecutionVerdict,
    WebImpactReplayIssue,
    WebImpactReplayTransportObservation,
    build_web_impact_execution_receipt,
    evaluate_web_impact_execution,
    parse_web_impact_operator_spec,
    plan_web_impact_execution,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _payload_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


VULNERABLE_BODY = b"victim-canary-secret-body"
CONTROL_BODY = b"patched-control-denied"
COOKIE_VALUE = b"Cookie: session=super-secret-token"


class WebImpactExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_manifest = _digest("source-manifest")
        self.image_digest = "sha256:" + "9" * 64
        self.vulnerable_target = WebImpactApprovedTarget(
            kind=WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
            binding_sha256=_digest("vulnerable-target"),
            generation=7,
        )
        self.control_target = WebImpactApprovedTarget(
            kind=WEB_IMPACT_ALLOWLISTED_TARGET_KIND,
            binding_sha256=_digest("control-target"),
            generation=3,
        )
        self.operator_document = self._operator_document()
        self.operator_payload = _json_bytes(self.operator_document)
        self.specification = self._parse(self.operator_payload)
        self.execution_plan = plan_web_impact_execution(
            self.specification,
            self._issues(3),
        )
        self.transports = self._transports(self.execution_plan)

    def _operator_document(
        self,
        *,
        differential: bool = False,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "authorized_target": self.vulnerable_target.to_dict(),
            "differential": None,
            "identities": [
                {
                    "principal_binding_sha256": _digest(
                        "principal:" + role
                    ),
                    "role": role,
                }
                for role in WEB_IDENTITY_ROLES
            ],
            "oracle": {
                "expected_response_sha256": _payload_digest(
                    VULNERABLE_BODY
                ),
                "expected_response_size_bytes": len(VULNERABLE_BODY),
                "expected_status": 200,
                "impact_kind": "authorization_bypass",
                "sink_step_ordinal": 3,
            },
            "protocol": WEB_IMPACT_OPERATOR_SPEC_PROTOCOL,
            "runtime_image_digest": self.image_digest,
            "schema_version": 1,
            "source_manifest_sha256": self.source_manifest,
            "source_sink": {
                "runtime_step_ordinal": 3,
                "sink_kind": "response_body",
                "sink_pointer_sha256": _digest("sink:pointer"),
                "source_kind": "request_parameter",
                "source_pointer_sha256": _digest("source:pointer"),
                "trace_contract_sha256": _digest("trace:contract"),
            },
            "timeline": [
                {
                    "channel": "http",
                    "expected_status": 201,
                    "method": "POST",
                    "ordinal": 1,
                    "request_shape_sha256": _digest("shape:create"),
                    "role": "user",
                    "route_binding_sha256": _digest("route:create"),
                },
                {
                    "channel": "browser",
                    "expected_status": 200,
                    "method": "GET",
                    "ordinal": 2,
                    "request_shape_sha256": _digest("shape:approve"),
                    "role": "admin",
                    "route_binding_sha256": _digest("route:approve"),
                },
                {
                    "channel": "http",
                    "expected_status": 200,
                    "method": "GET",
                    "ordinal": 3,
                    "request_shape_sha256": _digest("shape:extract"),
                    "role": "attacker",
                    "route_binding_sha256": _digest("route:extract"),
                },
            ],
        }
        if differential:
            result["differential"] = {
                "expected_response_sha256": _payload_digest(
                    CONTROL_BODY
                ),
                "expected_response_size_bytes": len(CONTROL_BODY),
                "expected_status": 403,
                "target": self.control_target.to_dict(),
            }
        return result

    def _parse(
        self,
        payload: bytes,
        *,
        differential: bool = False,
        **changes: object,
    ):
        values = {
            "current_source_manifest_sha256": self.source_manifest,
            "current_runtime_image_digest": self.image_digest,
            "current_vulnerable_target": self.vulnerable_target,
            "current_control_target": (
                self.control_target if differential else None
            ),
        }
        values.update(changes)
        return parse_web_impact_operator_spec(payload, **values)

    def _issues(self, count: int):
        return tuple(
            WebImpactReplayIssue(
                request_id=f"REQ-{ordinal}",
                run_id=f"RUN-{ordinal}",
                replay_nonce=hashlib.sha256(
                    f"nonce:{ordinal}".encode("ascii")
                ).digest(),
            )
            for ordinal in range(1, count + 1)
        )

    def _event_and_payloads(
        self,
        request,
        step,
    ) -> tuple[
        WebTimelineEvent,
        WebImpactCapturedArtifact,
        WebImpactCapturedArtifact,
    ]:
        prefix = (
            f"{request.replay_target_kind}:"
            f"{request.replay_ordinal}:{step.ordinal}"
        )
        request_body = (
            COOKIE_VALUE
            + b"\n"
            + f"request:{prefix}".encode("ascii")
        )
        control = request.replay_target_kind == "control"
        if step.ordinal == 3:
            response_body = CONTROL_BODY if control else VULNERABLE_BODY
            status = 403 if control else 200
        else:
            response_body = f"response:{prefix}".encode("ascii")
            status = step.expected_status
        request_artifact = WebArtifactCommitment(
            artifact_id=(
                f"A-{request.replay_target_kind}-"
                f"{request.replay_ordinal}-{step.ordinal}-request"
            ),
            sha256=_payload_digest(request_body),
            size_bytes=len(request_body),
        )
        response_artifact = WebArtifactCommitment(
            artifact_id=(
                f"A-{request.replay_target_kind}-"
                f"{request.replay_ordinal}-{step.ordinal}-response"
            ),
            sha256=_payload_digest(response_body),
            size_bytes=len(response_body),
        )
        event = WebTimelineEvent(
            ordinal=step.ordinal,
            channel=step.channel,
            role=step.role,
            method=step.method,
            route_binding_sha256=step.route_binding_sha256,
            request_shape_sha256=step.request_shape_sha256,
            status=status,
            request_artifact=request_artifact,
            response_artifact=response_artifact,
            cookie_transition_sha256=_digest(prefix + ":cookie-state"),
            security_context_sha256=_digest(prefix + ":security-context"),
        )
        return (
            event,
            WebImpactCapturedArtifact(
                artifact_id=request_artifact.artifact_id,
                payload=request_body,
            ),
            WebImpactCapturedArtifact(
                artifact_id=response_artifact.artifact_id,
                payload=response_body,
            ),
        )

    def _transport(
        self,
        execution_plan,
        request,
        *,
        receipt_id: str | None = None,
    ) -> WebImpactReplayTransportObservation:
        events: list[WebTimelineEvent] = []
        artifacts: list[WebImpactCapturedArtifact] = []
        for step in execution_plan.specification.plan.timeline:
            event, request_capture, response_capture = (
                self._event_and_payloads(request, step)
            )
            events.append(event)
            artifacts.extend((request_capture, response_capture))
        trace_payload = (
            b"runtime-trace-without-raw-log:"
            + request.run_id.encode("ascii")
        )
        trace = WebArtifactCommitment(
            artifact_id=(
                f"A-{request.replay_target_kind}-"
                f"{request.replay_ordinal}-trace"
            ),
            sha256=_payload_digest(trace_payload),
            size_bytes=len(trace_payload),
        )
        artifacts.append(
            WebImpactCapturedArtifact(
                artifact_id=trace.artifact_id,
                payload=trace_payload,
            )
        )
        runtime_event = events[
            execution_plan.specification.plan.source_sink.runtime_step_ordinal
            - 1
        ]
        observation = WebImpactReplayObservation(
            target_kind=request.replay_target_kind,
            replay_ordinal=request.replay_ordinal,
            run_id=request.run_id,
            receipt_id=(
                receipt_id
                if receipt_id is not None
                else f"RCPT-{request.run_id}"
            ),
            receipt_sha256="0" * 64,
            replay_nonce_sha256=request.replay_nonce_sha256,
            identity_epoch_sha256=request.identity_epoch_sha256,
            execution_contract_sha256=(
                request.semantic_execution_contract_sha256
            ),
            plan_sha256=request.plan_sha256,
            source_manifest_sha256=request.source_manifest_sha256,
            runtime_image_digest=request.runtime_image_digest,
            authorized_target_binding_sha256=(
                request.target.binding_sha256
            ),
            target_generation=request.target.generation,
            clean_workspace=True,
            fresh_identity_state=True,
            network_target_authorized=True,
            orchestration_status="completed",
            exit_code=0,
            timed_out=False,
            capture_complete=True,
            truncation_known=True,
            truncated=False,
            capture_error=None,
            timeline=tuple(events),
            source_sink=WebSourceSinkObservation(
                source_kind=(
                    execution_plan.specification.plan.source_sink.source_kind
                ),
                source_pointer_sha256=(
                    execution_plan.specification.plan.source_sink
                    .source_pointer_sha256
                ),
                sink_kind=(
                    execution_plan.specification.plan.source_sink.sink_kind
                ),
                sink_pointer_sha256=(
                    execution_plan.specification.plan.source_sink
                    .sink_pointer_sha256
                ),
                runtime_step_ordinal=(
                    execution_plan.specification.plan.source_sink
                    .runtime_step_ordinal
                ),
                runtime_request_sha256=(
                    runtime_event.request_artifact.sha256
                ),
                trace_contract_sha256=(
                    execution_plan.specification.plan.source_sink
                    .trace_contract_sha256
                ),
                trace_artifact=trace,
                reached_sink=not (
                    request.replay_target_kind == "control"
                ),
            ),
        )
        captured = tuple(artifacts)
        receipt = build_web_impact_execution_receipt(
            request,
            observation,
            captured,
            orchestration_status="completed",
            exit_code=0,
            timed_out=False,
            clean_workspace=True,
            fresh_identity_state=True,
            network_target_authorized=True,
            capture_complete=True,
            truncation_known=True,
            truncated=False,
            capture_error_code=None,
        )
        bound_observation = replace(
            observation,
            receipt_sha256=receipt.sha256,
        )
        return WebImpactReplayTransportObservation(
            request_payload=request.canonical_bytes,
            receipt_payload=receipt.canonical_bytes,
            semantic_observation=bound_observation,
            artifacts=captured,
        )

    def _transports(self, execution_plan):
        return tuple(
            self._transport(execution_plan, request)
            for request in execution_plan.requests
        )

    def _evaluate(
        self,
        *,
        execution_plan=None,
        transports=None,
        operator_payload=None,
        differential: bool = False,
        **changes: object,
    ):
        plan = (
            self.execution_plan
            if execution_plan is None
            else execution_plan
        )
        values = {
            "operator_spec_payload": (
                self.operator_payload
                if operator_payload is None
                else operator_payload
            ),
            "current_source_manifest_sha256": self.source_manifest,
            "current_runtime_image_digest": self.image_digest,
            "current_vulnerable_target": self.vulnerable_target,
            "current_control_target": (
                self.control_target if differential else None
            ),
        }
        values.update(changes)
        return evaluate_web_impact_execution(
            plan,
            self.transports if transports is None else transports,
            **values,
        )

    def _rebuild_transport(
        self,
        request,
        transport,
        *,
        observation=None,
        artifacts=None,
        receipt_changes: dict[str, object] | None = None,
    ):
        selected_observation = (
            transport.semantic_observation
            if observation is None
            else observation
        )
        selected_observation = replace(
            selected_observation,
            receipt_sha256="0" * 64,
        )
        selected_artifacts = (
            transport.artifacts if artifacts is None else artifacts
        )
        receipt = build_web_impact_execution_receipt(
            request,
            selected_observation,
            selected_artifacts,
            orchestration_status="completed",
            exit_code=0,
            timed_out=False,
            clean_workspace=True,
            fresh_identity_state=True,
            network_target_authorized=True,
            capture_complete=True,
            truncation_known=True,
            truncated=False,
            capture_error_code=None,
        )
        if receipt_changes:
            receipt = replace(receipt, **receipt_changes)
        selected_observation = replace(
            selected_observation,
            receipt_sha256=receipt.sha256,
            clean_workspace=receipt.clean_workspace,
            fresh_identity_state=receipt.fresh_identity_state,
            network_target_authorized=(
                receipt.network_target_authorized
            ),
            orchestration_status=receipt.orchestration_status,
            exit_code=receipt.exit_code,
            timed_out=receipt.timed_out,
            capture_complete=receipt.capture_complete,
            truncation_known=receipt.truncation_known,
            truncated=receipt.truncated,
            capture_error=(
                None
                if receipt.capture_error_code is None
                else receipt.capture_error_code
            ),
        )
        return WebImpactReplayTransportObservation(
            request_payload=request.canonical_bytes,
            receipt_payload=receipt.canonical_bytes,
            semantic_observation=selected_observation,
            artifacts=selected_artifacts,
        )

    def test_three_preissued_replays_confirm_only_impact_fact(self) -> None:
        result = self._evaluate()

        self.assertIs(
            result.verdict,
            WebImpactExecutionVerdict.CONFIRMED,
        )
        self.assertTrue(result.confirmed)
        self.assertEqual(len(result.records), 3)
        self.assertTrue(result.semantic_evaluation.passed)
        authorities = result.to_dict()["authorities"]
        self.assertTrue(authorities["web_impact_oracle_satisfied"])
        self.assertTrue(
            authorities["executed_web_impact_fact_authorized"]
        )
        self.assertFalse(authorities["flag_proven"])
        self.assertFalse(authorities["candidate_authorized"])
        self.assertFalse(authorities["challenge_proof_satisfied"])
        self.assertFalse(authorities["automatic_submission_authorized"])
        reduction = result.reduction_projection()
        self.assertIsNone(reduction["candidate"])
        self.assertIsNone(reduction["proof"])
        self.assertIsNone(reduction["impact"])
        self.assertFalse(reduction["automatic_submission"])
        self.assertEqual(
            reduction["executed_fact"]["provenance"],
            "executed",
        )

    def test_raw_body_cookie_and_token_values_never_serialize(self) -> None:
        result = self._evaluate()
        serialized = [
            result.canonical_bytes,
            self.execution_plan.canonical_bytes,
            self.specification.canonical_bytes,
        ]
        serialized.extend(
            request.canonical_bytes
            for request in self.execution_plan.requests
        )
        serialized.extend(
            transport.receipt_payload for transport in self.transports
        )

        for payload in serialized:
            self.assertNotIn(VULNERABLE_BODY, payload)
            self.assertNotIn(CONTROL_BODY, payload)
            self.assertNotIn(b"session=super-secret-token", payload)
            self.assertNotIn(b"Bearer ", payload)
        self.assertLess(len(result.canonical_bytes), 1024 * 1024)

    def test_optional_patched_target_requires_three_more_controls(
        self,
    ) -> None:
        document = self._operator_document(differential=True)
        payload = _json_bytes(document)
        specification = self._parse(payload, differential=True)
        execution_plan = plan_web_impact_execution(
            specification,
            self._issues(6),
        )
        transports = self._transports(execution_plan)
        result = self._evaluate(
            execution_plan=execution_plan,
            transports=transports,
            operator_payload=payload,
            differential=True,
        )

        self.assertTrue(result.confirmed)
        self.assertEqual(len(result.records), 6)
        self.assertEqual(
            [record.replay_target_kind for record in result.records],
            ["vulnerable"] * 3 + ["control"] * 3,
        )
        statement = result.reduction_projection()["executed_fact"][
            "statement"
        ]
        self.assertIn("patched/non-vulnerable controls", statement)

    def test_operator_spec_is_strict_bounded_and_value_free(self) -> None:
        cases: list[tuple[bytes, str]] = []
        extra_root = copy.deepcopy(self.operator_document)
        extra_root["cookie"] = "session=secret"
        cases.append(
            (
                _json_bytes(extra_root),
                "operator_spec_schema_invalid",
            )
        )
        extra_identity = copy.deepcopy(self.operator_document)
        extra_identity["identities"][0]["token"] = "secret"
        cases.append(
            (
                _json_bytes(extra_identity),
                "identity_schema_invalid",
            )
        )
        raw_oracle = copy.deepcopy(self.operator_document)
        raw_oracle["oracle"]["expected_response_body"] = "secret"
        cases.append(
            (
                _json_bytes(raw_oracle),
                "oracle_schema_invalid",
            )
        )
        duplicate_key = b'{"protocol":"a","protocol":"b"}\n'
        cases.append((duplicate_key, "operator_spec_json_invalid"))
        oversized = b" " * (WEB_IMPACT_OPERATOR_SPEC_MAX_BYTES + 1)
        cases.append((oversized, "operator_spec_size_exceeded"))

        for payload, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(
                    WebImpactExecutionPreflightError,
                    code,
                ):
                    self._parse(payload)

    def test_only_current_allowlisted_target_generation_is_accepted(
        self,
    ) -> None:
        wrong_kind = copy.deepcopy(self.operator_document)
        wrong_kind["authorized_target"]["kind"] = "raw_url"
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "vulnerable_target_invalid",
        ):
            self._parse(_json_bytes(wrong_kind))

        stale = replace(self.vulnerable_target, generation=8)
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "vulnerable_target_not_current",
        ):
            self._parse(
                self.operator_payload,
                current_vulnerable_target=stale,
            )

        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "unexpected_current_control_target",
        ):
            self._parse(
                self.operator_payload,
                current_control_target=self.control_target,
            )

    def test_role_order_and_browser_http_timeline_reuse_semantic_gate(
        self,
    ) -> None:
        wrong_roles = copy.deepcopy(self.operator_document)
        wrong_roles["identities"][0], wrong_roles["identities"][1] = (
            wrong_roles["identities"][1],
            wrong_roles["identities"][0],
        )
        only_http = copy.deepcopy(self.operator_document)
        for step in only_http["timeline"]:
            step["channel"] = "http"
        unordered = copy.deepcopy(self.operator_document)
        unordered["timeline"][0], unordered["timeline"][1] = (
            unordered["timeline"][1],
            unordered["timeline"][0],
        )
        for document in (wrong_roles, only_http, unordered):
            with self.subTest(document=document):
                with self.assertRaisesRegex(
                    WebImpactExecutionPreflightError,
                    "web_impact_plan_",
                ):
                    self._parse(_json_bytes(document))

    def test_planner_requires_full_wave_unique_ids_and_fresh_entropy(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "replay_issue_count_mismatch",
        ):
            plan_web_impact_execution(
                self.specification,
                self._issues(2),
            )
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "replay_issue_count_mismatch",
        ):
            plan_web_impact_execution(
                self.specification,
                itertools.repeat(self._issues(1)[0]),
            )

        issues = list(self._issues(3))
        issues[1] = replace(issues[1], run_id=issues[0].run_id)
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "issued_identifier_reused",
        ):
            plan_web_impact_execution(self.specification, issues)

        issues = list(self._issues(3))
        issues[1] = replace(
            issues[1],
            replay_nonce=issues[0].replay_nonce,
        )
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "nonce_reused",
        ):
            plan_web_impact_execution(self.specification, issues)

        issues = list(self._issues(3))
        issues[0] = replace(
            issues[0],
            replay_nonce=b"x" * (
                WEB_IMPACT_REPLAY_NONCE_MIN_BYTES - 1
            ),
        )
        with self.assertRaisesRegex(
            WebImpactExecutionPreflightError,
            "nonce_invalid",
        ):
            plan_web_impact_execution(self.specification, issues)

    def test_request_order_count_and_exact_bytes_prevent_cherry_picking(
        self,
    ) -> None:
        self.assertEqual(
            self._evaluate(transports=self.transports[:2]).reason_codes,
            ("transport_count_mismatch",),
        )
        reversed_result = self._evaluate(
            transports=tuple(reversed(self.transports))
        )
        self.assertEqual(
            reversed_result.reason_codes,
            ("replay-1:issued_request_mismatch",),
        )
        modified = list(self.transports)
        modified[0] = replace(
            modified[0],
            request_payload=modified[0].request_payload + b" ",
        )
        self.assertEqual(
            self._evaluate(transports=modified).reason_codes,
            ("replay-1:issued_request_mismatch",),
        )

    def test_operator_spec_is_reread_and_cannot_be_rebound(self) -> None:
        changed = copy.deepcopy(self.operator_document)
        changed["oracle"]["impact_kind"] = "confidentiality"
        result = self._evaluate(
            operator_payload=_json_bytes(changed),
        )
        self.assertIn(
            result.reason_codes[0],
            {
                "operator_spec_rebinding_detected",
                "operator_spec_revalidation_failed",
            },
        )

        stale_target = replace(self.vulnerable_target, generation=8)
        result = self._evaluate(
            current_vulnerable_target=stale_target,
        )
        self.assertEqual(
            result.reason_codes,
            ("current_binding_mismatch",),
        )

    def test_run_nonce_target_and_execution_contract_cannot_rebind(
        self,
    ) -> None:
        mutations = (
            {"run_id": "RUN-forged"},
            {"replay_nonce_sha256": _digest("forged-nonce")},
            {
                "execution_contract_sha256": _digest(
                    "forged-contract"
                )
            },
            {
                "authorized_target_binding_sha256": _digest(
                    "other-target"
                )
            },
            {"target_generation": 99},
        )
        for mutation in mutations:
            transports = list(self.transports)
            transports[0] = replace(
                transports[0],
                semantic_observation=replace(
                    transports[0].semantic_observation,
                    **mutation,
                ),
            )
            with self.subTest(mutation=tuple(mutation)):
                result = self._evaluate(transports=transports)
                self.assertEqual(
                    result.reason_codes,
                    (
                        "replay-1:"
                        "semantic_transport_binding_mismatch",
                    ),
                )

    def test_receipt_request_and_allowlist_attestation_are_exact(
        self,
    ) -> None:
        receipt = WebImpactExecutionReceipt.from_payload(
            self.transports[0].receipt_payload
        )
        cases = (
            (
                {"request_sha256": _digest("other-request")},
                "receipt_request_binding_mismatch",
            ),
            (
                {
                    "transport_execution_contract_sha256": _digest(
                        "other-execution-contract"
                    )
                },
                "receipt_request_binding_mismatch",
            ),
            (
                {"network_target_authorized": False},
                "transport_not_clean_success",
            ),
            (
                {"fresh_identity_state": False},
                "transport_not_clean_success",
            ),
            (
                {"clean_workspace": False},
                "transport_not_clean_success",
            ),
        )
        for mutation, code in cases:
            transports = list(self.transports)
            changed = replace(receipt, **mutation)
            transports[0] = replace(
                transports[0],
                receipt_payload=changed.canonical_bytes,
            )
            with self.subTest(mutation=tuple(mutation)):
                result = self._evaluate(transports=transports)
                self.assertEqual(
                    result.reason_codes,
                    (f"replay-1:{code}",),
                )

    def test_receipt_document_must_be_strict_canonical_and_raw_free(
        self,
    ) -> None:
        transports = list(self.transports)
        transports[0] = replace(
            transports[0],
            receipt_payload=transports[0].receipt_payload + b" ",
        )
        self.assertEqual(
            self._evaluate(transports=transports).reason_codes,
            ("replay-1:receipt_document_invalid",),
        )

        receipt = WebImpactExecutionReceipt.from_payload(
            self.transports[0].receipt_payload
        )
        with self.assertRaisesRegex(
            ValueError,
            "receipt_capture_error_code_invalid",
        ):
            replace(
                receipt,
                capture_error_code="session=secret",
            )

    def test_duplicate_receipt_and_artifact_ids_are_rejected(self) -> None:
        first_receipt = WebImpactExecutionReceipt.from_payload(
            self.transports[0].receipt_payload
        )
        transports = list(self.transports)
        transports[1] = self._transport(
            self.execution_plan,
            self.execution_plan.requests[1],
            receipt_id=first_receipt.receipt_id,
        )
        result = self._evaluate(transports=transports)
        self.assertEqual(
            result.reason_codes,
            ("replay-2:duplicate_run_or_receipt",),
        )

        transports = list(self.transports)
        first_artifact_id = transports[0].artifacts[0].artifact_id
        second = transports[1]
        second_events = list(second.semantic_observation.timeline)
        first_second_event = second_events[0]
        second_events[0] = replace(
            first_second_event,
            request_artifact=replace(
                first_second_event.request_artifact,
                artifact_id=first_artifact_id,
            ),
        )
        artifacts = list(second.artifacts)
        artifacts[0] = replace(
            artifacts[0],
            artifact_id=first_artifact_id,
        )
        observation = replace(
            second.semantic_observation,
            timeline=tuple(second_events),
        )
        transports[1] = self._rebuild_transport(
            self.execution_plan.requests[1],
            second,
            observation=observation,
            artifacts=tuple(artifacts),
        )
        result = self._evaluate(transports=transports)
        self.assertEqual(
            result.reason_codes,
            ("replay-2:duplicate_artifact_id",),
        )

    def test_actual_response_and_trace_bytes_are_independently_hashed(
        self,
    ) -> None:
        for artifact_index in (5, 6):
            transports = list(self.transports)
            first = transports[0]
            artifacts = list(first.artifacts)
            payload = artifacts[artifact_index].payload
            artifacts[artifact_index] = replace(
                artifacts[artifact_index],
                payload=(
                    b"X" + payload[1:]
                    if payload
                    else b"X"
                ),
            )
            transports[0] = replace(
                first,
                artifacts=tuple(artifacts),
            )
            with self.subTest(artifact_index=artifact_index):
                result = self._evaluate(transports=transports)
                self.assertEqual(
                    result.reason_codes,
                    ("replay-1:artifact_payload_mismatch",),
                )

    def test_semantic_oracle_is_reused_after_transport_verification(
        self,
    ) -> None:
        transports = list(self.transports)
        first = transports[0]
        events = list(first.semantic_observation.timeline)
        sink = events[2]
        forged_body = b"forged-success-body-value"
        events[2] = replace(
            sink,
            response_artifact=replace(
                sink.response_artifact,
                sha256=_payload_digest(forged_body),
                size_bytes=len(forged_body),
            ),
        )
        artifacts = list(first.artifacts)
        artifacts[5] = replace(
            artifacts[5],
            payload=forged_body,
        )
        observation = replace(
            first.semantic_observation,
            timeline=tuple(events),
        )
        transports[0] = self._rebuild_transport(
            self.execution_plan.requests[0],
            first,
            observation=observation,
            artifacts=tuple(artifacts),
        )
        result = self._evaluate(transports=transports)

        self.assertEqual(
            result.reason_codes,
            ("semantic_evaluation_rejected",),
        )
        self.assertIsNotNone(result.semantic_evaluation)
        self.assertTrue(
            any(
                "impact_oracle_failed" in code
                for code in result.semantic_evaluation.failure_codes
            )
        )
        self.assertIsNone(
            result.reduction_projection()["executed_fact"]
        )

    def test_forged_preissued_plan_is_rejected_before_transport(self) -> None:
        requests = list(self.execution_plan.requests)
        requests[0] = replace(
            requests[0],
            transport_execution_contract_sha256=_digest("forged"),
        )
        forged = replace(
            self.execution_plan,
            requests=tuple(requests),
        )
        result = self._evaluate(execution_plan=forged)

        self.assertEqual(
            result.reason_codes,
            ("execution_plan_invalid",),
        )

    def test_public_documents_are_protocol_and_size_bound(self) -> None:
        result = self._evaluate()
        self.assertEqual(
            result.to_dict()["protocol"],
            WEB_IMPACT_EXECUTION_PROTOCOL,
        )
        self.assertEqual(
            len(self.execution_plan.requests),
            3,
        )
        self.assertLess(
            len(self.specification.plan.canonical_bytes),
            64 * 1024,
        )
        self.assertLess(
            len(result.semantic_evaluation.canonical_bytes),
            512 * 1024,
        )


if __name__ == "__main__":
    unittest.main()
