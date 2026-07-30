from __future__ import annotations

import hashlib
import json
import unittest

from ctf_os.engine.web_active_probe import (
    WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
    WEB_ACTIVE_PROBE_HELPER_PROTOCOL,
    WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
    WebActiveProbeError,
    classify_web_active_probe_report,
    evaluate_web_active_probe_records,
    parse_web_active_probe_driver,
    parse_web_active_probe_operator_spec,
)
from ctf_os.engine.web_impact_driver import (
    WebImpactDriverInput,
    WebImpactDriverStep,
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(label: str) -> str:
    return _sha256(label.encode("ascii"))


def _json(value: object) -> bytes:
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


def _signature(label: str, status: int) -> dict[str, object]:
    payload = label.encode("ascii")
    return {
        "body_sha256": _sha256(payload),
        "body_size_bytes": len(payload),
        "status": status,
    }


def _input(locator: str, payload: bytes) -> WebImpactDriverInput:
    return WebImpactDriverInput(
        locator=locator,
        sha256=_sha256(payload),
        size_bytes=len(payload),
    )


def _step(
    ordinal: int,
    *,
    route: WebImpactDriverInput,
    body: WebImpactDriverInput | None,
) -> WebImpactDriverStep:
    return WebImpactDriverStep(
        ordinal=ordinal,
        channel="http",
        role="attacker",
        method="POST",
        route=route,
        body=body,
        follow=False,
        insecure=False,
        timeout_seconds=10,
    )


def _request(step: WebImpactDriverStep) -> dict[str, object]:
    return {
        "body_sha256": (
            step.body.sha256 if step.body is not None else None
        ),
        "body_size_bytes": (
            step.body.size_bytes if step.body is not None else None
        ),
        "method": step.method,
        "request_shape_sha256": step.request_shape_sha256,
        "route_sha256": step.route.sha256,
        "route_size_bytes": step.route.size_bytes,
    }


class WebActiveProbeTests(unittest.TestCase):
    def _documents(self, mode: str):
        setup_route = _input("setup.route", b"/login\n")
        setup_body = _input("setup.body", b"login")
        probe_route = _input("probe.route", b"/claim\n")
        probe_body = _input(
            "probe.body",
            (
                b'{"callback":"{{CTF_OOB_URL}}"}'
                if mode == "oob"
                else b'{"claim":true}'
            ),
        )
        setup = _step(
            1,
            route=setup_route,
            body=setup_body,
        )
        probe = _step(
            2,
            route=probe_route,
            body=probe_body,
        )
        oracle: dict[str, object]
        transport: dict[str, object]
        if mode == "race":
            oracle = {
                "control": _signature("control", 409),
                "impact": _signature("won", 200),
                "minimum_impact_count": 1,
                "vulnerable_nonimpact": _signature("lost", 409),
            }
            transport = {"attempts": 2, "concurrency": 2}
        else:
            oracle = {
                "callback": {
                    "body_sha256": _sha256(b"callback"),
                    "body_size_bytes": len(b"callback"),
                    "method": "POST",
                },
                "control_trigger": _signature("blocked", 403),
                "vulnerable_trigger": _signature("queued", 202),
            }
            transport = {"callback_timeout_seconds": 5}
        spec = {
            "control_target": {
                "binding_sha256": _digest("control-target"),
                "generation": 1,
                "kind": "allowlisted_http_origin_v1",
            },
            "identity": {
                "principal_binding_sha256": _digest("attacker"),
                "role": "attacker",
            },
            "mode": mode,
            "oracle": oracle,
            "probe": _request(probe),
            "protocol": WEB_ACTIVE_PROBE_OPERATOR_PROTOCOL,
            "runtime_image_digest": "sha256:" + ("6" * 64),
            "schema_version": 1,
            "setup": [
                {
                    "expected_response": _signature(
                        "logged-in",
                        200,
                    ),
                    "request": _request(setup),
                }
            ],
            "source_manifest_sha256": _digest("manifest"),
            "transport": transport,
            "vulnerable_target": {
                "binding_sha256": _digest("vulnerable-target"),
                "generation": 1,
                "kind": "allowlisted_http_origin_v1",
            },
        }
        spec_payload = _json(spec)

        def project(step: WebImpactDriverStep) -> dict[str, object]:
            value = step.to_dict()
            value.pop("channel")
            value.pop("role")
            return value

        driver = {
            "control_target_id": "target-control",
            "operator_spec_sha256": _sha256(spec_payload),
            "probe": project(probe),
            "protocol": WEB_ACTIVE_PROBE_DRIVER_PROTOCOL,
            "schema_version": 1,
            "setup": [project(setup)],
            "vulnerable_target_id": "target-vulnerable",
        }
        return (
            parse_web_active_probe_operator_spec(spec_payload),
            parse_web_active_probe_driver(
                _json(driver),
                operator_spec_payload=spec_payload,
            ),
            spec_payload,
        )

    @staticmethod
    def _race_report(
        *,
        target_kind: str,
        control_impact: bool = False,
    ) -> dict[str, object]:
        bodies = (
            [b"won", b"lost", b"lost", b"lost"]
            if target_kind == "vulnerable" or control_impact
            else [b"control"] * 4
        )
        statuses = [
            200 if payload == b"won" else 409
            for payload in bodies
        ]
        responses = []
        for ordinal, (body, status) in enumerate(
            zip(bodies, statuses, strict=True),
            start=1,
        ):
            responses.append(
                {
                    "artifact": f"response-{ordinal:04d}.bin",
                    "attempt": ((ordinal - 1) // 2) + 1,
                    "body_sha256": _sha256(body),
                    "body_size_bytes": len(body),
                    "duration_ns": 1000,
                    "index": ((ordinal - 1) % 2) + 1,
                    "ordinal": ordinal,
                    "status": status,
                    "truncated": False,
                }
            )
        for offset in (0, 2):
            digest = _sha256(_json(responses[offset : offset + 2]))
            for response in responses[offset : offset + 2]:
                response["batch_sha256"] = digest
        return {
            "artifact_names": [
                item["artifact"] for item in responses
            ],
            "attempts": 2,
            "concurrency": 2,
            "cookie_transition_sha256": _digest("transition"),
            "elapsed_ns": 10000,
            "mode": "race",
            "protocol": WEB_ACTIVE_PROBE_HELPER_PROTOCOL,
            "request_count": 4,
            "responses": responses,
            "schema_version": 1,
            "session": "attacker",
            "timeline_ordinal": 2,
        }

    @staticmethod
    def _record(
        ordinal: int,
        target_kind: str,
        classified: dict[str, object],
    ) -> dict[str, object]:
        return {
            **classified,
            "cookie_lineage_after_sha256": _digest(
                f"after-{ordinal}"
            ),
            "cookie_lineage_before_sha256": _digest(
                f"before-{ordinal}"
            ),
            "identity_epoch_sha256": _digest(f"epoch-{ordinal}"),
            "ordinal": ordinal,
            "receipt_id": f"WAPR-{ordinal}",
            "report_sha256": _digest(f"report-{ordinal}"),
            "run_id": f"WAPRUN-{ordinal}",
            "target_kind": target_kind,
            "timeline_sha256": _digest(f"timeline-{ordinal}"),
        }

    def test_race_requires_three_positive_and_three_exact_controls(
        self,
    ) -> None:
        spec, driver, spec_payload = self._documents("race")
        self.assertEqual(driver.operator_spec_sha256, _sha256(spec_payload))
        records = []
        for ordinal in range(1, 7):
            target_kind = (
                "vulnerable" if ordinal <= 3 else "control"
            )
            classified = classify_web_active_probe_report(
                spec,
                self._race_report(target_kind=target_kind),
                target_kind=target_kind,
            )
            self.assertTrue(classified["passed"])
            records.append(
                self._record(ordinal, target_kind, classified)
            )
        evaluation = evaluate_web_active_probe_records(
            operator_spec_sha256=_sha256(spec_payload),
            mode="race",
            records=tuple(records),
        )
        self.assertTrue(evaluation["confirmed"])
        self.assertTrue(
            evaluation["authorities"][
                "web_active_probe_oracle_satisfied"
            ]
        )
        self.assertFalse(
            evaluation["authorities"]["candidate_authorized"]
        )
        self.assertNotIn(
            "private-cookie-value",
            json.dumps(evaluation),
        )

        hostile = classify_web_active_probe_report(
            spec,
            self._race_report(
                target_kind="control",
                control_impact=True,
            ),
            target_kind="control",
        )
        self.assertFalse(hostile["passed"])
        self.assertIn(
            "control_emitted_impact_signature",
            hostile["reason_codes"],
        )

    def test_oob_requires_callback_only_on_vulnerable_target(
        self,
    ) -> None:
        spec, _driver, spec_payload = self._documents("oob")

        def report(target_kind: str) -> dict[str, object]:
            vulnerable = target_kind == "vulnerable"
            callbacks = (
                [
                    {
                        "body_sha256": _sha256(b"callback"),
                        "body_size_bytes": len(b"callback"),
                        "header_names_sha256": _digest("headers"),
                        "method": "POST",
                        "path_sha256": _digest("path"),
                    }
                ]
                if vulnerable
                else []
            )
            trigger_body = b"queued" if vulnerable else b"blocked"
            return {
                "artifact_names": ["trigger-response.bin"],
                "callback_count": len(callbacks),
                "callbacks": callbacks,
                "cookie_transition_sha256": _digest("transition"),
                "elapsed_ns": 10000,
                "mode": "oob",
                "protocol": WEB_ACTIVE_PROBE_HELPER_PROTOCOL,
                "rendered_request_sha256": _digest("rendered"),
                "rendered_request_size_bytes": 64,
                "schema_version": 1,
                "session": "attacker",
                "timeline_ordinal": 2,
                "trigger": {
                    "body_sha256": _sha256(trigger_body),
                    "body_size_bytes": len(trigger_body),
                    "duration_ns": 1000,
                    "status": 202 if vulnerable else 403,
                    "truncated": False,
                },
            }

        records = []
        for ordinal in range(1, 7):
            target_kind = (
                "vulnerable" if ordinal <= 3 else "control"
            )
            classified = classify_web_active_probe_report(
                spec,
                report(target_kind),
                target_kind=target_kind,
            )
            self.assertTrue(classified["passed"])
            records.append(
                self._record(ordinal, target_kind, classified)
            )
        evaluation = evaluate_web_active_probe_records(
            operator_spec_sha256=_sha256(spec_payload),
            mode="oob",
            records=tuple(records),
        )
        self.assertTrue(evaluation["confirmed"])

        hostile = report("control")
        hostile["callbacks"] = report("vulnerable")["callbacks"]
        hostile["callback_count"] = 1
        classified = classify_web_active_probe_report(
            spec,
            hostile,
            target_kind="control",
        )
        self.assertFalse(classified["passed"])
        self.assertIn(
            "oob_control_received_callback",
            classified["reason_codes"],
        )

    def test_schema_tamper_and_raw_driver_value_reject(
        self,
    ) -> None:
        _spec, driver, spec_payload = self._documents("race")
        value = json.loads(driver.canonical_bytes)
        value["probe"]["route"]["locator"] = "../cookie.jar"
        with self.assertRaises(WebActiveProbeError):
            parse_web_active_probe_driver(
                _json(value),
                operator_spec_payload=spec_payload,
            )
        spec_value = json.loads(spec_payload)
        spec_value["identity"]["cookie"] = "private-cookie-value"
        with self.assertRaises(WebActiveProbeError):
            parse_web_active_probe_operator_spec(
                _json(spec_value)
            )


if __name__ == "__main__":
    unittest.main()
