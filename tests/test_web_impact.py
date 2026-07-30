from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.engine.web_impact import (
    WEB_IDENTITY_ROLES,
    WEB_IMPACT_REPLAY_COUNT,
    WebArtifactCommitment,
    WebDifferentialPolicy,
    WebIdentityBinding,
    WebImpactOracle,
    WebImpactPreflightError,
    WebImpactReplayObservation,
    WebImpactVerdict,
    WebSourceSinkContract,
    WebSourceSinkObservation,
    WebTimelineEvent,
    WebTimelineStep,
    build_web_impact_plan,
    evaluate_web_impact,
    web_identity_epoch_sha256,
    web_replay_execution_contract_sha256,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class WebImpactContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identities = tuple(
            WebIdentityBinding(
                role=role,
                principal_binding_sha256=_digest("principal:" + role),
            )
            for role in WEB_IDENTITY_ROLES
        )
        self.timeline = (
            WebTimelineStep(
                ordinal=1,
                channel="http",
                role="user",
                method="POST",
                route_binding_sha256=_digest("route:create"),
                request_shape_sha256=_digest("shape:create"),
                expected_status=201,
            ),
            WebTimelineStep(
                ordinal=2,
                channel="browser",
                role="admin",
                method="GET",
                route_binding_sha256=_digest("route:approve"),
                request_shape_sha256=_digest("shape:approve"),
                expected_status=200,
            ),
            WebTimelineStep(
                ordinal=3,
                channel="http",
                role="attacker",
                method="GET",
                route_binding_sha256=_digest("route:extract"),
                request_shape_sha256=_digest("shape:extract"),
                expected_status=200,
            ),
        )
        self.source_sink = WebSourceSinkContract(
            source_kind="request_parameter",
            source_pointer_sha256=_digest("source:pointer"),
            sink_kind="response_body",
            sink_pointer_sha256=_digest("sink:pointer"),
            runtime_step_ordinal=3,
            trace_contract_sha256=_digest("trace:contract"),
        )
        self.oracle = WebImpactOracle(
            impact_kind="authorization_bypass",
            sink_step_ordinal=3,
            expected_status=200,
            expected_response_sha256=_digest("vulnerable:impact"),
            expected_response_size_bytes=17,
        )
        self.plan = self._plan()

    def _plan(
        self,
        *,
        identities=None,
        timeline=None,
        source_sink=None,
        oracle=None,
        differential=None,
    ):
        return build_web_impact_plan(
            source_manifest_sha256=_digest("source-manifest"),
            runtime_image_digest="sha256:" + "9" * 64,
            authorized_target_binding_sha256=_digest(
                "authorized-vulnerable-target"
            ),
            target_generation=4,
            identities=self.identities if identities is None else identities,
            timeline=self.timeline if timeline is None else timeline,
            source_sink=(
                self.source_sink
                if source_sink is None
                else source_sink
            ),
            oracle=self.oracle if oracle is None else oracle,
            differential=differential,
        )

    def _event(
        self,
        plan,
        *,
        target_kind: str,
        replay_ordinal: int,
        step: WebTimelineStep,
    ) -> WebTimelineEvent:
        control = target_kind == "control"
        prefix = f"{target_kind}:{replay_ordinal}:{step.ordinal}"
        status = (
            plan.differential.expected_status
            if control
            and plan.differential is not None
            and step.ordinal == plan.oracle.sink_step_ordinal
            else step.expected_status
        )
        if step.ordinal == plan.oracle.sink_step_ordinal:
            response_sha256 = (
                plan.differential.expected_response_sha256
                if control and plan.differential is not None
                else plan.oracle.expected_response_sha256
            )
            response_size = (
                plan.differential.expected_response_size_bytes
                if control and plan.differential is not None
                else plan.oracle.expected_response_size_bytes
            )
        else:
            response_sha256 = _digest(prefix + ":response")
            response_size = 50 + step.ordinal
        return WebTimelineEvent(
            ordinal=step.ordinal,
            channel=step.channel,
            role=step.role,
            method=step.method,
            route_binding_sha256=step.route_binding_sha256,
            request_shape_sha256=step.request_shape_sha256,
            status=status,
            request_artifact=WebArtifactCommitment(
                artifact_id=(
                    f"A-{target_kind}-{replay_ordinal}-"
                    f"{step.ordinal}-request"
                ),
                sha256=_digest(prefix + ":request"),
                size_bytes=40 + step.ordinal,
            ),
            response_artifact=WebArtifactCommitment(
                artifact_id=(
                    f"A-{target_kind}-{replay_ordinal}-"
                    f"{step.ordinal}-response"
                ),
                sha256=response_sha256,
                size_bytes=response_size,
            ),
            cookie_transition_sha256=_digest(prefix + ":cookies"),
            security_context_sha256=_digest(prefix + ":security"),
        )

    def _observation(
        self,
        plan,
        target_kind: str,
        replay_ordinal: int,
    ) -> WebImpactReplayObservation:
        events = tuple(
            self._event(
                plan,
                target_kind=target_kind,
                replay_ordinal=replay_ordinal,
                step=step,
            )
            for step in plan.timeline
        )
        nonce = _digest(
            f"nonce:{target_kind}:{replay_ordinal}"
        )
        control = target_kind == "control"
        target_binding = (
            plan.differential.control_target_binding_sha256
            if control and plan.differential is not None
            else plan.authorized_target_binding_sha256
        )
        target_generation = (
            plan.differential.control_target_generation
            if control and plan.differential is not None
            else plan.target_generation
        )
        runtime_event = events[
            plan.source_sink.runtime_step_ordinal - 1
        ]
        return WebImpactReplayObservation(
            target_kind=target_kind,
            replay_ordinal=replay_ordinal,
            run_id=f"RUN-{target_kind}-{replay_ordinal}",
            receipt_id=f"RCPT-{target_kind}-{replay_ordinal}",
            receipt_sha256=_digest(
                f"receipt:{target_kind}:{replay_ordinal}"
            ),
            replay_nonce_sha256=nonce,
            identity_epoch_sha256=web_identity_epoch_sha256(
                plan,
                nonce,
            ),
            execution_contract_sha256=(
                web_replay_execution_contract_sha256(
                    plan,
                    target_kind=target_kind,
                    replay_ordinal=replay_ordinal,
                    replay_nonce_sha256=nonce,
                )
            ),
            plan_sha256=plan.plan_sha256,
            source_manifest_sha256=plan.source_manifest_sha256,
            runtime_image_digest=plan.runtime_image_digest,
            authorized_target_binding_sha256=target_binding,
            target_generation=target_generation,
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
            timeline=events,
            source_sink=WebSourceSinkObservation(
                source_kind=plan.source_sink.source_kind,
                source_pointer_sha256=(
                    plan.source_sink.source_pointer_sha256
                ),
                sink_kind=plan.source_sink.sink_kind,
                sink_pointer_sha256=(
                    plan.source_sink.sink_pointer_sha256
                ),
                runtime_step_ordinal=(
                    plan.source_sink.runtime_step_ordinal
                ),
                runtime_request_sha256=(
                    runtime_event.request_artifact.sha256
                ),
                trace_contract_sha256=(
                    plan.source_sink.trace_contract_sha256
                ),
                trace_artifact=WebArtifactCommitment(
                    artifact_id=(
                        f"A-{target_kind}-{replay_ordinal}-trace"
                    ),
                    sha256=_digest(
                        f"trace:{target_kind}:{replay_ordinal}"
                    ),
                    size_bytes=512,
                ),
                reached_sink=not control,
            ),
        )

    def _observations(self, plan=None):
        selected = self.plan if plan is None else plan
        values = [
            self._observation(
                selected,
                "vulnerable",
                ordinal,
            )
            for ordinal in range(1, WEB_IMPACT_REPLAY_COUNT + 1)
        ]
        if selected.differential is not None:
            values.extend(
                self._observation(selected, "control", ordinal)
                for ordinal in range(
                    1,
                    WEB_IMPACT_REPLAY_COUNT + 1,
                )
            )
        return tuple(values)

    def test_three_fresh_replays_confirm_only_web_impact(self) -> None:
        evaluation = evaluate_web_impact(
            self.plan,
            self._observations(),
        )

        self.assertIs(evaluation.verdict, WebImpactVerdict.CONFIRMED)
        self.assertTrue(evaluation.passed)
        self.assertEqual(len(evaluation.replay_records), 3)
        authorities = evaluation.to_dict()["authorities"]
        self.assertTrue(authorities["web_impact_oracle_satisfied"])
        self.assertTrue(
            authorities["executed_web_impact_fact_authorized"]
        )
        self.assertFalse(authorities["flag_proven"])
        self.assertFalse(authorities["candidate_authorized"])
        self.assertFalse(authorities["challenge_proof_satisfied"])
        self.assertFalse(authorities["self_report_accepted"])
        self.assertFalse(authorities["automatic_submission_authorized"])

        reduction = evaluation.reduction_projection()
        self.assertEqual(
            reduction["executed_fact"]["provenance"],
            "executed",
        )
        self.assertIsNone(reduction["candidate"])
        self.assertIsNone(reduction["proof"])
        self.assertFalse(reduction["automatic_submission"])

    def test_serialized_contract_is_value_free_and_target_is_hash_only(
        self,
    ) -> None:
        evaluation = evaluate_web_impact(
            self.plan,
            self._observations(),
        )
        encoded = evaluation.canonical_bytes.decode("ascii")

        for secret in (
            "https://target.internal",
            "session=super-secret",
            "Bearer token-value",
            "victim-canary-value",
        ):
            self.assertNotIn(secret, encoded)
        plan_target = evaluation.to_dict()["plan"]["authorized_target"]
        self.assertEqual(
            set(plan_target),
            {"binding_sha256", "generation"},
        )
        self.assertLess(len(evaluation.canonical_bytes), 512 * 1024)

    def test_all_three_identity_bindings_are_exact_and_value_free(self) -> None:
        with self.assertRaisesRegex(
            WebImpactPreflightError,
            "identity_bindings_invalid",
        ):
            self._plan(identities=self.identities[:2])
        with self.assertRaisesRegex(
            WebImpactPreflightError,
            "identity_bindings_invalid",
        ):
            self._plan(
                identities=(
                    self.identities[1],
                    self.identities[0],
                    self.identities[2],
                )
            )
        duplicate = replace(
            self.identities[2],
            principal_binding_sha256=(
                self.identities[0].principal_binding_sha256
            ),
        )
        with self.assertRaisesRegex(
            WebImpactPreflightError,
            "identity_bindings_invalid",
        ):
            self._plan(
                identities=(
                    self.identities[0],
                    self.identities[1],
                    duplicate,
                )
            )

    def test_timeline_requires_ordered_http_and_browser_steps(self) -> None:
        only_http = tuple(
            replace(step, channel="http")
            for step in self.timeline
        )
        unordered = (
            self.timeline[1],
            self.timeline[0],
            self.timeline[2],
        )
        for timeline in (only_http, unordered):
            with self.subTest(timeline=timeline):
                with self.assertRaisesRegex(
                    WebImpactPreflightError,
                    "timeline_invalid",
                ):
                    self._plan(timeline=timeline)

    def test_replay_count_freshness_and_clean_transport_are_required(
        self,
    ) -> None:
        observations = list(self._observations())
        self.assertIn(
            "replay_count_mismatch",
            evaluate_web_impact(
                self.plan,
                observations[:2],
            ).failure_codes,
        )

        repeated = list(observations)
        repeated[1] = replace(
            repeated[1],
            replay_nonce_sha256=repeated[0].replay_nonce_sha256,
            identity_epoch_sha256=repeated[0].identity_epoch_sha256,
        )
        failures = evaluate_web_impact(
            self.plan,
            repeated,
        ).failure_codes
        self.assertTrue(
            any("freshness_nonce_invalid_or_reused" in item for item in failures)
        )

        unclean = list(observations)
        unclean[0] = replace(
            unclean[0],
            fresh_identity_state=False,
        )
        self.assertTrue(
            any(
                "transport_invalid" in item
                for item in evaluate_web_impact(
                    self.plan,
                    unclean,
                ).failure_codes
            )
        )

        repeated_receipt = list(observations)
        repeated_receipt[1] = replace(
            repeated_receipt[1],
            receipt_sha256=repeated_receipt[0].receipt_sha256,
        )
        self.assertTrue(
            any(
                "receipt_hash_invalid_or_reused" in item
                for item in evaluate_web_impact(
                    self.plan,
                    repeated_receipt,
                ).failure_codes
            )
        )

    def test_target_source_runtime_and_identity_epoch_are_bound(self) -> None:
        base = self._observations()
        mutations = (
            {
                "authorized_target_binding_sha256": _digest(
                    "unapproved-target"
                )
            },
            {"source_manifest_sha256": _digest("stale-source")},
            {"runtime_image_digest": "sha256:" + "7" * 64},
            {"identity_epoch_sha256": _digest("forged-epoch")},
        )
        for mutation in mutations:
            observations = list(base)
            observations[0] = replace(observations[0], **mutation)
            with self.subTest(mutation=tuple(mutation)):
                failures = evaluate_web_impact(
                    self.plan,
                    observations,
                ).failure_codes
                self.assertTrue(
                    any(
                        "execution_binding_mismatch" in item
                        for item in failures
                    )
                )

    def test_request_response_hashes_and_order_are_not_self_reported(
        self,
    ) -> None:
        observations = list(self._observations())
        events = list(observations[0].timeline)
        sink = events[2]
        events[2] = replace(
            sink,
            response_artifact=replace(
                sink.response_artifact,
                sha256=_digest("model-says-success"),
            ),
        )
        observations[0] = replace(
            observations[0],
            timeline=tuple(events),
        )
        failures = evaluate_web_impact(
            self.plan,
            observations,
        ).failure_codes
        self.assertTrue(
            any("impact_oracle_failed" in item for item in failures)
        )

        observations = list(self._observations())
        swapped = list(observations[0].timeline)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        observations[0] = replace(
            observations[0],
            timeline=tuple(swapped),
        )
        failures = evaluate_web_impact(
            self.plan,
            observations,
        ).failure_codes
        self.assertTrue(any("timeline_invalid" in item for item in failures))

        observations = list(self._observations())
        observations[0] = replace(
            observations[0],
            timeline=observations[0].timeline[:1],
        )
        evaluation = evaluate_web_impact(self.plan, observations)
        self.assertFalse(evaluation.passed)
        self.assertTrue(
            any(
                "timeline_invalid" in item
                for item in evaluation.failure_codes
            )
        )

    def test_source_to_sink_trace_is_request_bound_and_must_reach_sink(
        self,
    ) -> None:
        observations = list(self._observations())
        observations[0] = replace(
            observations[0],
            source_sink=replace(
                observations[0].source_sink,
                runtime_request_sha256=_digest("foreign-request"),
            ),
        )
        failures = evaluate_web_impact(
            self.plan,
            observations,
        ).failure_codes
        self.assertTrue(
            any("source_sink_evidence_invalid" in item for item in failures)
        )

        observations = list(self._observations())
        observations[0] = replace(
            observations[0],
            source_sink=replace(
                observations[0].source_sink,
                reached_sink=False,
            ),
        )
        failures = evaluate_web_impact(
            self.plan,
            observations,
        ).failure_codes
        self.assertTrue(
            any("source_sink_evidence_invalid" in item for item in failures)
        )

    def test_declared_differential_requires_three_exact_controls(self) -> None:
        policy = WebDifferentialPolicy(
            control_target_binding_sha256=_digest("patched-target"),
            control_target_generation=6,
            expected_status=403,
            expected_response_sha256=_digest("patched:denied"),
            expected_response_size_bytes=9,
        )
        plan = self._plan(differential=policy)
        evaluation = evaluate_web_impact(
            plan,
            self._observations(plan),
        )
        self.assertTrue(evaluation.passed)
        self.assertEqual(len(evaluation.replay_records), 6)

        missing_controls = evaluate_web_impact(
            plan,
            self._observations(plan)[:3],
        )
        self.assertFalse(missing_controls.passed)
        self.assertIn(
            "replay_count_mismatch",
            missing_controls.failure_codes,
        )

        controls_reach_sink = list(self._observations(plan))
        controls_reach_sink[3] = replace(
            controls_reach_sink[3],
            source_sink=replace(
                controls_reach_sink[3].source_sink,
                reached_sink=True,
            ),
        )
        failures = evaluate_web_impact(
            plan,
            controls_reach_sink,
        ).failure_codes
        self.assertTrue(
            any("source_sink_evidence_invalid" in item for item in failures)
        )

    def test_undeclared_control_and_wrong_control_oracle_fail_closed(
        self,
    ) -> None:
        extra = (
            *self._observations(),
            {"target_kind": "control"},
        )
        evaluation = evaluate_web_impact(self.plan, extra)
        self.assertIn("replay_count_mismatch", evaluation.failure_codes)

        policy = WebDifferentialPolicy(
            control_target_binding_sha256=_digest("patched-target"),
            control_target_generation=6,
            expected_status=403,
            expected_response_sha256=_digest("patched:denied"),
            expected_response_size_bytes=9,
        )
        plan = self._plan(differential=policy)
        observations = list(self._observations(plan))
        events = list(observations[3].timeline)
        events[2] = replace(
            events[2],
            response_artifact=replace(
                events[2].response_artifact,
                sha256=_digest("patched-but-wrong"),
            ),
        )
        observations[3] = replace(
            observations[3],
            timeline=tuple(events),
        )
        failures = evaluate_web_impact(
            plan,
            observations,
        ).failure_codes
        self.assertTrue(
            any("impact_oracle_failed" in item for item in failures)
        )

    def test_oracle_and_differential_cannot_be_identical(self) -> None:
        policy = WebDifferentialPolicy(
            control_target_binding_sha256=_digest("patched-target"),
            control_target_generation=6,
            expected_status=self.oracle.expected_status,
            expected_response_sha256=(
                self.oracle.expected_response_sha256
            ),
            expected_response_size_bytes=(
                self.oracle.expected_response_size_bytes
            ),
        )
        with self.assertRaisesRegex(
            WebImpactPreflightError,
            "differential_policy_invalid",
        ):
            self._plan(differential=policy)

    def test_untyped_model_claim_is_not_an_observation(self) -> None:
        observations = list(self._observations())
        observations[0] = {
            "self_reported_success": True,
            "flag": "KCTF{not-proof}",
        }
        evaluation = evaluate_web_impact(
            self.plan,
            observations,
        )
        self.assertFalse(evaluation.passed)
        self.assertTrue(
            any(
                "observation_type_invalid" in item
                for item in evaluation.failure_codes
            )
        )
        encoded = json.dumps(
            evaluation.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
        )
        self.assertNotIn("KCTF{not-proof}", encoded)


if __name__ == "__main__":
    unittest.main()
