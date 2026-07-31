from __future__ import annotations

import copy
import http.server
import json
import multiprocessing
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import deque
from pathlib import Path
from unittest import mock

import ctf_os.codex.limiter as limiter_module
import ctf_os.codex.runner as runner_module
from ctf_os.codex import (
    ROLE_SPECS,
    BatchCommandBuilder,
    BatchInvocation,
    BatchRunner,
    BatchWave,
    BatchWaveRunner,
    BuiltCommand,
    EventAccumulator,
    FifoModelCallLimiter,
    FileFifoModelCallLimiter,
    FlagNotificationError,
    LimiterSnapshot,
    LiveCommandBuilder,
    LiveSession,
    ModelCatalog,
    ModelFamily,
    ProcessOutcome,
    ReasoningEffort,
    Role,
    SubprocessExecutor,
    role_output_schema,
    validate_role_output,
)
from ctf_os.codex.events import FlagDetector as EventFlagDetector
from ctf_os.codex.limiter import ModelCallLimitCancelled


def valid_payload(role: Role, *, flag: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "role": role.value,
        "status": "ok",
        "summary": "bounded result",
        "observations": [
            {
                "id": "obs-1",
                "claim": "The executable returned a marker.",
                "evidence": ["runs/tool-output.txt:1"],
                "provenance": "executed",
            }
        ],
        "hypotheses": [
            {
                "id": "hyp-1",
                "statement": "The marker controls the branch.",
                "observation_refs": ["obs-from-existing-state"],
                "falsifier": "Change the marker and rerun.",
                "keep_if": "The branch changes.",
                "drop_if": "The branch does not change.",
            }
        ],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [
            {
                "kind": "command",
                "description": "Run the discriminating test.",
                "command": "./solver --probe",
                "artifact_path": None,
            }
        ],
        "artifacts": [],
        "progress_markers": [{"name": "branch_reached", "evidence": "trace line 4"}],
        "flag_candidates": (
            [{"value": flag, "source": "tool_output", "evidence": "stdout line 8"}]
            if flag is not None
            else []
        ),
        "decision": (
            {"next_stage": "attack", "reason": "One path survived falsification."}
            if role is Role.CAPTAIN
            else None
        ),
        "goal_update": None,
        "refusal": None,
    }


def _output_path(command: BuiltCommand) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


def _file_limiter_worker(
    state_path: str,
    number: int,
    release_event,
    result_queue,
    cancel_event=None,
) -> None:
    limiter = FileFifoModelCallLimiter(
        Path(state_path),
        1,
        poll_interval=0.005,
    )
    started = time.monotonic()
    try:
        with limiter.slot(
            timeout=5,
            cancel_event=cancel_event,
        ) as model_call_slot:
            waited = model_call_slot.acquire()
            result_queue.put(("acquired", number, waited))
            release_event.wait(timeout=5)
    except RuntimeError as error:
        result_queue.put(
            ("cancelled", number, time.monotonic() - started, str(error))
        )


def _file_limiter_acquire_then_die(
    state_path: str,
    acquired_event,
) -> None:
    limiter = FileFifoModelCallLimiter(
        Path(state_path),
        1,
        poll_interval=0.005,
    )
    with limiter.slot(timeout=2) as model_call_slot:
        model_call_slot.acquire()
        acquired_event.set()
        os._exit(0)


def _hold_model_limiter_lock(
    lock_path: str,
    ready_event,
    hold_seconds: float,
) -> None:
    path = Path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        limiter_module.fcntl.flock(
            descriptor,
            limiter_module.fcntl.LOCK_EX,
        )
        ready_event.set()
        time.sleep(hold_seconds)
    finally:
        limiter_module.fcntl.flock(
            descriptor,
            limiter_module.fcntl.LOCK_UN,
        )
        os.close(descriptor)


def _stop_test_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
    process.join(timeout=2)


def _wait_file_limiter_state(
    state_path: Path,
    *,
    active: int,
    waiting: int,
    timeout: float = 2,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last: dict[str, object] | None = None
    while time.monotonic() < deadline:
        try:
            value = json.loads(state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.005)
            continue
        if isinstance(value, dict):
            last = value
            holders = value.get("holders")
            queued = value.get("queue")
            if (
                isinstance(holders, list)
                and isinstance(queued, list)
                and len(holders) == active
                and len(queued) == waiting
            ):
                return value
        time.sleep(0.005)
    raise AssertionError(
        f"limiter did not reach active={active}, waiting={waiting}: {last}"
    )


class ScriptedExecutor:
    def __init__(self, scripts: list[tuple[list[dict[str, object]], object, int]]) -> None:
        self.scripts = scripts
        self.commands: list[BuiltCommand] = []

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, timeout
        self.commands.append(command)
        events, output, returncode = self.scripts.pop(0)
        started = time.monotonic()
        for event in events:
            on_stdout_line(json.dumps(event) + "\n")
        _output_path(command).write_text(json.dumps(output), encoding="utf-8")
        return ProcessOutcome(returncode, "", time.monotonic() - started)


class SuccessfulSlowExecutor:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls = 0

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, timeout
        with self.lock:
            self.active += 1
            self.calls += 1
            self.max_active = max(self.max_active, self.active)
            call_number = self.calls
        try:
            on_stdout_line(
                json.dumps({"type": "thread.started", "thread_id": f"thread-{call_number}"})
                + "\n"
            )
            time.sleep(0.04)
            _output_path(command).write_text(
                json.dumps(valid_payload(Role.RECON)), encoding="utf-8"
            )
            return ProcessOutcome(0, "", 0.04)
        finally:
            with self.lock:
                self.active -= 1


class SelectiveFailureExecutor:
    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, timeout
        output_path = _output_path(command)
        if "run-2" in str(output_path):
            raise OSError("synthetic launch failure")
        on_stdout_line(
            json.dumps(
                {"type": "thread.started", "thread_id": output_path.parent.name}
            )
            + "\n"
        )
        output_path.write_text(json.dumps(valid_payload(Role.RECON)), encoding="utf-8")
        return ProcessOutcome(0, "", 0.0)


class ContractTests(unittest.TestCase):
    def test_role_routes_cover_sol_terra_luna_and_proof_separation(self) -> None:
        self.assertEqual(ROLE_SPECS[Role.CAPTAIN].model_family, ModelFamily.SOL)
        self.assertEqual(ROLE_SPECS[Role.RECON].model_family, ModelFamily.TERRA)
        self.assertEqual(ROLE_SPECS[Role.EXTRACTOR].model_family, ModelFamily.LUNA)
        self.assertEqual(ROLE_SPECS[Role.VALIDATOR].model_family, ModelFamily.SOL)
        self.assertEqual(
            ROLE_SPECS[Role.EVIDENCE_AUDITOR].model_family, ModelFamily.LUNA
        )
        self.assertNotEqual(Role.FALSIFIER, Role.EVIDENCE_AUDITOR)
        self.assertNotEqual(Role.REPRODUCER, Role.VALIDATOR)

    def test_strict_contract_uses_canonical_provenance(self) -> None:
        result = validate_role_output(valid_payload(Role.RECON), Role.RECON)
        self.assertTrue(result.valid, result.errors)
        schema = role_output_schema(Role.RECON)
        provenance = schema["properties"]["observations"]["items"]["properties"][
            "provenance"
        ]["enum"]
        self.assertEqual(
            provenance,
            ["executed", "tool_inferred", "model_claimed", "external_doc", "operator"],
        )

    def test_managed_v2_action_contract_is_explicit_and_v1_is_stable(
        self,
    ) -> None:
        v1_schema = role_output_schema(Role.RECON)
        self.assertNotIn(
            "hypothesis_ids",
            v1_schema["properties"]["actions"]["items"]["properties"],
        )

        payload = valid_payload(Role.RECON)
        payload["schema_version"] = 2
        payload["hypotheses"] = [
            {
                "id": "hyp-1",
                "claim": "The marker controls the branch.",
                "evidence": ["obs-1"],
                "unknowns": ["Whether another byte also gates the branch."],
                "experiment": "Change only the marker and rerun.",
                "success_oracle": "The traced branch changes.",
                "falsifier": "The same branch is taken for both markers.",
            }
        ]
        payload["actions"][0].update(
            {
                "hypothesis_ids": ["H-existing"],
                "expected_observation": "the branch changes",
                "keep_if": "the changed branch is reproduced",
                "drop_if": "the branch remains unchanged",
                "timeout_seconds": 90,
                "resource_class": "standard",
                "network_target_id": "T-primary",
                "network_target_generation": 3,
            }
        )
        result = validate_role_output(
            payload,
            Role.RECON,
            contract_version=2,
        )
        self.assertTrue(result.valid, result.errors)
        v2_schema = role_output_schema(
            Role.RECON,
            contract_version=2,
        )
        self.assertEqual(
            v2_schema["properties"]["schema_version"]["enum"],
            [2],
        )
        self.assertIn(
            "network_target_generation",
            v2_schema["properties"]["actions"]["items"]["anyOf"][0][
                "required"
            ],
        )
        action_variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in v2_schema["properties"]["actions"]["items"]["anyOf"]
        }
        command_schema = action_variants["command"]["properties"][
            "command"
        ]
        self.assertEqual(command_schema["type"], "string")
        self.assertEqual(command_schema["minLength"], 1)
        self.assertIn("/bin/sh -lc <script>", command_schema["description"])
        self.assertIn("not an argv", command_schema["description"])
        self.assertEqual(
            action_variants["command"]["properties"]["artifact_path"],
            {"type": "null"},
        )
        self.assertNotIn(
            "uniqueItems",
            action_variants["command"]["properties"]["hypothesis_ids"],
        )
        hypothesis_schema = v2_schema["properties"]["hypotheses"]["items"]
        self.assertIn("claim", hypothesis_schema["required"])
        self.assertIn("evidence", hypothesis_schema["required"])
        self.assertIn("unknowns", hypothesis_schema["required"])
        self.assertIn("experiment", hypothesis_schema["required"])
        self.assertIn("success_oracle", hypothesis_schema["required"])
        self.assertNotIn("statement", hypothesis_schema["properties"])

        payload["actions"][0]["network_target_generation"] = None
        payload["actions"][0]["expected_observation"] = ""
        result = validate_role_output(
            payload,
            Role.RECON,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        joined = "\n".join(result.errors)
        self.assertIn("provided together", joined)
        self.assertIn("requires text", joined)

    def test_managed_v2_hypothesis_requires_complete_discriminators(
        self,
    ) -> None:
        payload = valid_payload(Role.RECON)
        payload["schema_version"] = 2
        payload["hypotheses"] = [
            {
                "id": "hyp-1",
                "claim": "The marker controls the branch.",
                "evidence": ["obs-1"],
                "unknowns": [],
                "experiment": "",
                "success_oracle": "",
                "falsifier": "",
            }
        ]
        payload["actions"][0].update(
            {
                "hypothesis_ids": [],
                "expected_observation": "the branch is traced",
                "keep_if": "the trace is present",
                "drop_if": "the trace is absent",
                "timeout_seconds": 30,
                "resource_class": "light",
                "network_target_id": None,
                "network_target_generation": None,
            }
        )

        result = validate_role_output(
            payload,
            Role.RECON,
            contract_version=2,
        )

        self.assertFalse(result.valid)
        joined = "\n".join(result.errors)
        self.assertIn("$.hypotheses[0].unknowns", joined)
        self.assertIn("$.hypotheses[0].experiment", joined)
        self.assertIn("$.hypotheses[0].success_oracle", joined)
        self.assertIn("$.hypotheses[0].falsifier", joined)

    def test_managed_proof_action_is_minimal_and_reproducer_only(
        self,
    ) -> None:
        payload = valid_payload(Role.REPRODUCER)
        payload["schema_version"] = 2
        payload["hypotheses"] = []
        payload["actions"] = [
            {
                "kind": "prove_candidate",
                "description": "Replay the canonical tool result.",
                "candidate_id": "C-tool-1",
                "inputs": [
                    {
                        "artifact_id": "A-solver",
                        "purpose": "reproducer",
                    }
                ],
            }
        ]

        result = validate_role_output(
            payload,
            Role.REPRODUCER,
            contract_version=2,
        )

        self.assertTrue(result.valid, result.errors)
        schema = role_output_schema(
            Role.REPRODUCER,
            contract_version=2,
        )
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"]["anyOf"]
        }
        proof = variants["prove_candidate"]
        self.assertEqual(
            set(proof["properties"]),
            {"kind", "description", "candidate_id", "inputs"},
        )
        self.assertEqual(
            set(proof["properties"]["inputs"]["items"]["properties"]),
            {"artifact_id", "purpose"},
        )
        purpose_values = proof["properties"]["inputs"]["items"][
            "properties"
        ]["purpose"]["enum"]
        self.assertIn("accepted_input", purpose_values)
        rev_payload = copy.deepcopy(payload)
        rev_payload["actions"][0]["inputs"][0][
            "purpose"
        ] = "accepted_input"
        result = validate_role_output(
            rev_payload,
            Role.REPRODUCER,
            contract_version=2,
        )
        self.assertTrue(result.valid, result.errors)

        wrong_role = copy.deepcopy(payload)
        wrong_role["role"] = Role.VALIDATOR.value
        result = validate_role_output(
            wrong_role,
            Role.VALIDATOR,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "restricted to the v2 reproducer",
            "\n".join(result.errors),
        )

        payload["actions"][0]["repetitions"] = 1
        payload["actions"][0]["oracle"] = "model-selected"
        result = validate_role_output(
            payload,
            Role.REPRODUCER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn("unexpected keys", "\n".join(result.errors))

    def test_managed_pwn_crash_action_is_minimal_and_builder_only(
        self,
    ) -> None:
        payload = valid_payload(Role.BUILDER)
        payload["schema_version"] = 2
        payload["hypotheses"] = []
        payload["actions"] = [
            {
                "kind": "verify_pwn_crash",
                "description": "Check the reported stdin PoC.",
                "payload_artifact_path": "artifacts/workspace/crash.bin",
                "hypothesis_id": "hyp-crash",
            }
        ]

        result = validate_role_output(
            payload,
            Role.BUILDER,
            contract_version=2,
        )

        self.assertTrue(result.valid, result.errors)
        schema = role_output_schema(
            Role.BUILDER,
            contract_version=2,
        )
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"]["anyOf"]
        }
        crash = variants["verify_pwn_crash"]
        self.assertEqual(
            set(crash["properties"]),
            {
                "kind",
                "description",
                "payload_artifact_path",
                "hypothesis_id",
            },
        )

        escaped = copy.deepcopy(payload)
        escaped["actions"][0]["payload_artifact_path"] = "../crash.bin"
        result = validate_role_output(
            escaped,
            Role.BUILDER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "expected safe relative path",
            "\n".join(result.errors),
        )

        wrong_role = copy.deepcopy(payload)
        wrong_role["role"] = Role.REPRODUCER.value
        result = validate_role_output(
            wrong_role,
            Role.REPRODUCER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "restricted to the v2 builder",
            "\n".join(result.errors),
        )

        injected = copy.deepcopy(payload)
        injected["actions"][0]["command"] = "kill -SEGV $$"
        result = validate_role_output(
            injected,
            Role.BUILDER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn("unexpected keys", "\n".join(result.errors))

    def test_managed_typed_category_gates_are_exact_builder_contracts(
        self,
    ) -> None:
        actions = {
            "prove_pwn_exploit_effect": {
                "kind": "prove_pwn_exploit_effect",
                "description": "Replay the proved control primitive.",
                "parent_experiment_id": "E-ip-control",
                "payload_artifact_path": "exploit.bin",
                "timeout_seconds": 300,
            },
            "prove_web_impact": {
                "kind": "prove_web_impact",
                "description": "Run the exact multi-session impact plan.",
                "operator_spec_artifact_path": "web/spec.json",
                "driver_artifact_path": "web/driver.json",
                "hypothesis_ids": ["H-web"],
                "timeout_seconds": 900,
            },
            "prove_web_active_probe": {
                "kind": "prove_web_active_probe",
                "description": "Run the exact race/OOB differential plan.",
                "operator_spec_artifact_path": "web/active-spec.json",
                "driver_artifact_path": "web/active-driver.json",
                "hypothesis_ids": ["H-web-active"],
                "timeout_seconds": 900,
            },
            "prove_crypto_metamorphic": {
                "kind": "prove_crypto_metamorphic",
                "description": "Run the original and mutated parameters.",
                "candidate_id": "C-crypto",
                "solver_artifact_path": "crypto/solver.py",
                "original_parameters_artifact_path": "crypto/original.json",
                "oracle_preissue_id": "oracle-preissue-crypto-1",
                "runtime": "python",
            },
            "prove_forensic_assertion": {
                "kind": "prove_forensic_assertion",
                "description": "Corroborate the assertion independently.",
                "operator_spec_artifact_path": "forensic/spec.json",
                "hypothesis_ids": [],
                "timeout_seconds": 900,
            },
            "evaluate_misc_transform": {
                "kind": "evaluate_misc_transform",
                "description": "Execute and reverse-check the transform DAG.",
                "candidate_id": "C-misc",
                "spec_artifact_path": "misc/spec.json",
                "oracle_preissue_id": "oracle-preissue-misc-1",
            },
        }
        schema = role_output_schema(
            Role.BUILDER,
            contract_version=2,
        )
        variants = {
            item["properties"]["kind"]["enum"][0]: item
            for item in schema["properties"]["actions"]["items"]["anyOf"]
        }
        for kind, action in actions.items():
            with self.subTest(kind=kind):
                payload = valid_payload(Role.BUILDER)
                payload["schema_version"] = 2
                payload["hypotheses"] = []
                payload["actions"] = [copy.deepcopy(action)]
                result = validate_role_output(
                    payload,
                    Role.BUILDER,
                    contract_version=2,
                )
                self.assertTrue(result.valid, result.errors)
                self.assertEqual(
                    set(variants[kind]["properties"]),
                    set(action),
                )

                wrong_role = copy.deepcopy(payload)
                wrong_role["role"] = Role.REPRODUCER.value
                result = validate_role_output(
                    wrong_role,
                    Role.REPRODUCER,
                    contract_version=2,
                )
                self.assertFalse(result.valid)
                self.assertIn(
                    "restricted to the v2 builder",
                    "\n".join(result.errors),
                )

                mutated = copy.deepcopy(payload)
                mutated["actions"][0]["verdict"] = "passed"
                result = validate_role_output(
                    mutated,
                    Role.BUILDER,
                    contract_version=2,
                )
                self.assertFalse(result.valid)
                self.assertIn(
                    "unexpected keys",
                    "\n".join(result.errors),
                )

        escaped = valid_payload(Role.BUILDER)
        escaped["schema_version"] = 2
        escaped["hypotheses"] = []
        escaped["actions"] = [copy.deepcopy(actions["prove_web_impact"])]
        escaped["actions"][0]["driver_artifact_path"] = "../driver.json"
        result = validate_role_output(
            escaped,
            Role.BUILDER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "expected safe relative path",
            "\n".join(result.errors),
        )

        bad_timeout = valid_payload(Role.BUILDER)
        bad_timeout["schema_version"] = 2
        bad_timeout["hypotheses"] = []
        bad_timeout["actions"] = [
            copy.deepcopy(actions["prove_pwn_exploit_effect"])
        ]
        bad_timeout["actions"][0]["timeout_seconds"] = True
        result = validate_role_output(
            bad_timeout,
            Role.BUILDER,
            contract_version=2,
        )
        self.assertFalse(result.valid)
        self.assertIn(
            "timeout_seconds",
            "\n".join(result.errors),
        )

    def test_contract_rejects_extra_keys_wrong_decision_and_readonly_write(self) -> None:
        payload = valid_payload(Role.FALSIFIER)
        payload["extra"] = True
        payload["decision"] = {"next_stage": "proof", "reason": "not this role's choice"}
        payload["actions"] = [
            {
                "kind": "write_artifact",
                "description": "bad",
                "command": None,
                "artifact_path": "solver.py",
            }
        ]
        result = validate_role_output(payload, Role.FALSIFIER)
        self.assertFalse(result.valid)
        joined = "\n".join(result.errors)
        self.assertIn("unexpected keys", joined)
        self.assertIn("read-only", joined)
        self.assertIn("may not make engine decisions", joined)

    def test_contract_rejects_path_escape_and_requires_captain_decision(self) -> None:
        payload = valid_payload(Role.CAPTAIN)
        payload["decision"] = None
        payload["artifacts"] = [
            {"path": "../escape", "sha256": None, "purpose": "bad path"}
        ]
        result = validate_role_output(payload, Role.CAPTAIN)
        self.assertFalse(result.valid)
        joined = "\n".join(result.errors)
        self.assertIn("safe relative path", joined)
        self.assertIn("must choose a next stage", joined)

    def test_contract_rejects_nonprintable_flag_candidate(self) -> None:
        for character in (
            "\t",
            "\u0085",
            "\u200b",
            "\u2028",
            "\u2029",
            "\u202e",
        ):
            with self.subTest(character=ascii(character)):
                payload = valid_payload(
                    Role.RECON,
                    flag=f"KCTF{{bad{character}flag}}",
                )
                result = validate_role_output(payload, Role.RECON)

                self.assertFalse(result.valid)
                self.assertTrue(
                    any(
                        "$.flag_candidates[0].value" in error
                        for error in result.errors
                    )
                )
        candidate_schema = role_output_schema(Role.RECON)["properties"][
            "flag_candidates"
        ]["items"]["properties"]["value"]
        self.assertEqual(candidate_schema["minLength"], 1)
        self.assertEqual(candidate_schema["maxLength"], 1024)
        self.assertIn("pattern", candidate_schema)

    def test_typed_goal_hypothesis_and_evaluation_contract_is_strict(
        self,
    ) -> None:
        schema = role_output_schema(Role.CAPTAIN)
        self.assertIn("goal_update", schema["required"])
        self.assertIn("hypothesis_updates", schema["required"])
        self.assertIn("evaluations", schema["required"])

        payload = valid_payload(Role.FALSIFIER)
        payload["goal_update"] = {
            "action": "create",
            "goal_id": "local-goal",
            "description": "forbidden non-captain goal",
            "depends_on": [],
            "artifact_ids": [],
            "blocked_reason": None,
            "activate": True,
        }
        payload["evaluations"] = [
            {
                "experiment_id": "E-existing",
                "status": "inconclusive",
                "reason": "did not discriminate",
                "evidence_fact_ids": [],
                "evidence_artifact_ids": [],
                "evidence_run_ids": [],
                "support_hypothesis_ids": ["H-existing"],
                "refute_hypothesis_ids": ["H-existing"],
            }
        ]
        result = validate_role_output(payload, Role.FALSIFIER)
        self.assertFalse(result.valid)
        joined = "\n".join(result.errors)
        self.assertIn("may not update goals", joined)
        self.assertIn("support/refute sets overlap", joined)
        self.assertIn("inconclusive cannot change hypotheses", joined)

        payload = valid_payload(Role.FALSIFIER)
        payload["hypothesis_updates"] = [
            {
                "hypothesis_id": "H-existing",
                "statement": None,
                "falsifier": None,
                "status": "refuted",
                "evidence_fact_ids": ["F-executed"],
                "evidence_artifact_ids": ["A-output"],
                "evidence_run_ids": ["R-tool"],
                "confidence": 0.1,
                "refuted_by": "F-executed",
            }
        ]
        result = validate_role_output(payload, Role.FALSIFIER)
        self.assertTrue(result.valid, result.errors)


class CommandTests(unittest.TestCase):
    def test_batch_command_has_role_model_effort_sandbox_and_stdin_prompt(self) -> None:
        invocation = BatchInvocation(
            "extract-1",
            Role.EXTRACTOR,
            "structure this output",
            Path("/challenge"),
            Path("/runs/extract-1"),
        )
        command = BatchCommandBuilder(
            models=ModelCatalog(sol="sol-id", terra="terra-id", luna="luna-id")
        ).build(invocation, Path("/tmp/schema.json"), Path("/tmp/output.json"))
        self.assertEqual(command.argv[:2], ("codex", "exec"))
        self.assertIn("luna-id", command.argv)
        self.assertIn('model_reasoning_effort="max"', command.argv)
        self.assertIn("read-only", command.argv)
        self.assertIn("features.shell_tool=false", command.argv)
        self.assertIn("features.unified_exec=false", command.argv)
        self.assertIn("features.multi_agent=false", command.argv)
        self.assertIn("agents.enabled=false", command.argv)
        self.assertIn('web_search="disabled"', command.argv)
        self.assertIn("features.apps=false", command.argv)
        self.assertIn("apps._default.enabled=false", command.argv)
        self.assertIn("features.plugins=false", command.argv)
        self.assertIn("features.remote_plugin=false", command.argv)
        self.assertIn(
            "features.remote_compaction_v2=true",
            command.argv,
        )
        self.assertIn(
            "features.enable_request_compression=true",
            command.argv,
        )
        self.assertIn("mcp_servers={}", command.argv)
        self.assertIn("plugins={}", command.argv)
        self.assertIn("--ignore-user-config", command.argv)
        self.assertIn("--ignore-rules", command.argv)
        self.assertIn("--strict-config", command.argv)
        self.assertEqual(command.argv[-1], "-")
        self.assertIn("Do not spawn or delegate", command.stdin)

    def test_batch_and_live_commands_honor_explicit_effort_overrides(self) -> None:
        invocation = BatchInvocation(
            "recon-effort",
            Role.RECON,
            "inspect",
            Path("/challenge"),
            Path("/runs/recon-effort"),
            reasoning_effort=ReasoningEffort.HIGH,
        )
        batch = BatchCommandBuilder().build(
            invocation, Path("/tmp/schema.json"), Path("/tmp/output.json")
        )
        self.assertIn('model_reasoning_effort="high"', batch.argv)
        live = LiveCommandBuilder().start(
            LiveSession(
                "live-effort",
                Path("/challenge"),
                "solve",
                reasoning_effort=ReasoningEffort.XHIGH,
            )
        )
        self.assertIn('model_reasoning_effort="xhigh"', live.argv)

    def test_invocations_reject_untyped_effort_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "ReasoningEffort"):
            BatchInvocation(
                "bad-effort",
                Role.RECON,
                "inspect",
                Path("/challenge"),
                Path("/runs/bad-effort"),
                reasoning_effort="extreme",  # type: ignore[arg-type]
            )

    def test_batch_resume_uses_supported_resume_options_only(self) -> None:
        invocation = BatchInvocation(
            "recon-1", Role.RECON, "inspect", Path("/challenge"), Path("/runs/recon-1")
        )
        command = BatchCommandBuilder().build(
            invocation,
            Path("/tmp/schema.json"),
            Path("/tmp/output.json"),
            resume_thread_id="thread-123",
            correction="missing role",
        )
        self.assertEqual(command.argv[:4], ("codex", "exec", "resume", "thread-123"))
        self.assertNotIn("--sandbox", command.argv)
        self.assertNotIn("-C", command.argv)
        self.assertIn("features.shell_tool=false", command.argv)
        self.assertIn("features.multi_agent=false", command.argv)
        self.assertIn("mcp_servers={}", command.argv)
        self.assertIn("--ignore-user-config", command.argv)
        self.assertIn("--ignore-rules", command.argv)
        self.assertIn("failed the local contract validator", command.stdin)

    def test_live_command_keeps_three_logical_workers_and_interactive_stdin(self) -> None:
        session = LiveSession("live-1", Path("/challenge"), "solve this")
        builder = LiveCommandBuilder(models=ModelCatalog(sol="sol-id"))
        start = builder.start(session)
        self.assertEqual(start.argv[0], "codex")
        self.assertNotIn("exec", start.argv)
        self.assertIn("agents.max_concurrent_threads_per_session=4", start.argv)
        self.assertIn("recon, specialist, falsifier", start.argv[-1])
        environment_policy = next(
            value
            for value in start.argv
            if value.startswith("shell_environment_policy.include_only=")
        )
        self.assertNotIn('"CTFOS_*"', environment_policy)
        self.assertNotIn('"CTFOS_SCOPE_CAPABILITY"', environment_policy)
        self.assertNotIn('"CTFOS_LIVE_BROKER_DIR"', environment_policy)
        self.assertIn("features.shell_tool=false", start.argv)
        self.assertIn("features.unified_exec=false", start.argv)
        self.assertIn("features.multi_agent=true", start.argv)
        self.assertIn("agents.enabled=true", start.argv)
        self.assertIn('web_search="disabled"', start.argv)
        self.assertIn("features.apps=false", start.argv)
        self.assertIn("apps._default.enabled=false", start.argv)
        self.assertIn("features.plugins=false", start.argv)
        self.assertIn("features.remote_plugin=false", start.argv)
        self.assertIn(
            "features.remote_compaction_v2=true",
            start.argv,
        )
        self.assertIn(
            "features.enable_request_compression=true",
            start.argv,
        )
        self.assertIn("features.browser_use=false", start.argv)
        self.assertIn("features.image_generation=false", start.argv)
        self.assertIn("mcp_servers={}", start.argv)
        self.assertIn("plugins={}", start.argv)
        self.assertIn("--strict-config", start.argv)
        self.assertIn("mcp_servers.ctfos_live.required=true", start.argv)
        self.assertIn(
            (
                "mcp_servers.ctfos_live.command="
                f"{json.dumps(os.path.abspath(sys.executable))}"
            ),
            start.argv,
        )
        self.assertIn(
            (
                "mcp_servers.ctfos_live.args="
                f'{json.dumps(["-I", "-m", "ctf_os.live_mcp"])}'
            ),
            start.argv,
        )
        self.assertIn(
            (
                'mcp_servers.ctfos_live.'
                'default_tools_approval_mode="approve"'
            ),
            start.argv,
        )
        self.assertIn(
            "immediately call ctfos_live agent.flag",
            start.argv[-1],
        )
        self.assertIn(
            "Never only print a candidate",
            start.argv[-1],
        )
        self.assertIn(
            "only relative paths beneath",
            start.argv[-1],
        )
        self.assertNotIn(
            "print it plainly",
            start.argv[-1],
        )
        forwarded = next(
            value
            for value in start.argv
            if value.startswith("mcp_servers.ctfos_live.env_vars=")
        )
        self.assertIn("CTFOS_SCOPE_CAPABILITY", forwarded)
        self.assertIn("CTFOS_LIVE_BROKER_DIR", forwarded)
        self.assertEqual(start.stdin, "")
        resumed = builder.resume(session, "thread-123")
        self.assertEqual(resumed.argv[:3], ("codex", "resume", "thread-123"))
        self.assertIn("features.shell_tool=false", resumed.argv)
        self.assertIn("mcp_servers.ctfos_live.required=true", resumed.argv)
        for command in (start, resumed):
            enabled_tools = next(
                value
                for value in command.argv
                if value.startswith(
                    "mcp_servers.ctfos_live.enabled_tools="
                )
            )
            self.assertEqual(
                set(json.loads(enabled_tools.split("=", 1)[1])),
                {
                    "agent.flag",
                    "agent.fact",
                    "agent.goal",
                    "agent.hypothesis",
                    "agent.experiment",
                    "agent.evaluate",
                    "agent.artifact",
                    "agent.progress",
                    "agent.transition",
                    "tool.start",
                    "tool.run",
                    "jobs",
                    "inspect",
                    "knowledge.search",
                    "knowledge.read",
                },
            )
            self.assertNotIn(
                ("-c", "-c"),
                tuple(zip(command.argv, command.argv[1:])),
            )

    def test_live_codex_request_exposes_only_scoped_and_local_tools(self) -> None:
        codex = shutil.which("codex")
        if codex is None:
            self.skipTest("codex CLI is not installed")

        captured: list[bytes] = []

        class CaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/v1/models":
                    self.send_error(404)
                    return
                models = [
                    {
                        "slug": model_id,
                        "id": model_id,
                        "object": "model",
                        "created": 0,
                        "owned_by": "ctfos-review",
                        "display_name": model_id,
                        "description": "local CTF-OS tool-surface review model",
                        "default_reasoning_level": "medium",
                        "supported_reasoning_levels": [
                            {
                                "effort": "medium",
                                "description": "local review",
                            }
                        ],
                        "shell_type": "shell_command",
                        "visibility": "list",
                        "supported_in_api": True,
                        "priority": 0,
                    }
                    for model_id in (
                        "ctfos-review-model",
                        ModelCatalog().resolve(ModelFamily.SOL),
                    )
                ]
                payload = json.dumps(
                    {
                        "object": "list",
                        # Codex 0.145 has both an OpenAI-compatible model-list
                        # decoder and a Codex catalog decoder on this path.
                        "data": models,
                        "models": models,
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                captured.append(self.rfile.read(length))
                payload = json.dumps(
                    {
                        "error": {
                            "message": "intentional local review stop",
                            "type": "invalid_request_error",
                        }
                    }
                ).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        server_thread = threading.Thread(
            target=server.serve_forever,
            name="codex-tool-capture",
            daemon=True,
        )
        server_thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                mailbox = root / "mailbox"
                mailbox.mkdir(mode=0o700)
                session = LiveSession("review-live", root, "review tool surface")
                built = LiveCommandBuilder(executable=codex).start(session)

                config_args: list[str] = []
                for index, argument in enumerate(built.argv[:-1]):
                    if argument == "-c":
                        config_args.extend(("-c", built.argv[index + 1]))
                self.assertIn("--strict-config", built.argv)

                port = server.server_address[1]
                provider_args = (
                    "-c",
                    'model_provider="ctfos_review_mock"',
                    "-c",
                    'model_providers.ctfos_review_mock.name="CTF-OS review mock"',
                    "-c",
                    (
                        "model_providers.ctfos_review_mock.base_url="
                        f'"http://127.0.0.1:{port}/v1"'
                    ),
                    "-c",
                    (
                        "model_providers.ctfos_review_mock.env_key="
                        '"CTFOS_REVIEW_DUMMY_KEY"'
                    ),
                    "-c",
                    "model_providers.ctfos_review_mock.request_max_retries=0",
                    "-c",
                    "model_providers.ctfos_review_mock.stream_max_retries=0",
                )
                config_args.extend(provider_args)
                capability = "review-secret-capability-9f15b73"
                environment = {
                    **os.environ,
                    "CTFOS_REVIEW_DUMMY_KEY": "not-a-real-key",
                    "CTFOS_LIVE_SESSION": "1",
                    "CTFOS_LIVE_BROKER_DIR": str(mailbox),
                    "CTFOS_SCOPE_CAPABILITY": capability,
                    "CTFOS_CONTEST": "review-contest",
                    "CTFOS_CATEGORY": "review-category",
                    "CTFOS_CHALLENGE": "review-challenge",
                }
                command = [
                    codex,
                    "--strict-config",
                    *config_args,
                    "exec",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "--json",
                    "--model",
                    "ctfos-review-model",
                    "-C",
                    str(root),
                    "capture the configured tool surface",
                ]
                try:
                    completed = subprocess.run(
                        command,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                except subprocess.TimeoutExpired as error:
                    self.fail(f"local Codex tool capture timed out: {error}")

                self.assertTrue(
                    captured,
                    (
                        "Codex did not reach the local mock provider; "
                        f"returncode={completed.returncode}, stderr={completed.stderr[-2000:]}"
                    ),
                )
                request = json.loads(captured[-1])
                tools = request.get("tools")
                self.assertIsInstance(tools, list)
                names = {
                    item.get("name") or item.get("type")
                    for item in tools
                    if isinstance(item, dict)
                }
                self.assertEqual(
                    names,
                    {
                        "list_mcp_resources",
                        "list_mcp_resource_templates",
                        "read_mcp_resource",
                        "update_plan",
                        "request_user_input",
                        "view_image",
                        "multi_agent_v1",
                        "mcp__ctfos_live",
                    },
                )
                self.assertNotIn("web_search", names)
                self.assertNotIn("request_plugin_install", names)
                self.assertFalse(
                    any(
                        isinstance(name, str)
                        and name.startswith("mcp__codex_apps__")
                        for name in names
                    )
                )
                self.assertTrue(
                    names.isdisjoint(
                        {
                            "exec",
                            "exec_command",
                            "write_stdin",
                            "shell",
                            "shell_command",
                        }
                    )
                )
                request_bytes = captured[-1]
                self.assertNotIn(capability.encode("utf-8"), request_bytes)
                self.assertNotIn(str(mailbox).encode("utf-8"), request_bytes)

                production_command = list(command)
                model_index = production_command.index("--model") + 1
                production_command[model_index] = ModelCatalog().resolve(
                    ModelFamily.SOL
                )
                capture_count = len(captured)
                try:
                    production_completed = subprocess.run(
                        production_command,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                except subprocess.TimeoutExpired as error:
                    self.fail(
                        f"production-model Codex tool capture timed out: {error}"
                    )
                self.assertGreater(
                    len(captured),
                    capture_count,
                    (
                        "Codex did not send the production-model request; "
                        f"returncode={production_completed.returncode}, "
                        f"stderr={production_completed.stderr[-2000:]}"
                    ),
                )
                production_bytes = captured[-1]
                production_request = json.loads(production_bytes)
                additional_tools = [
                    tool
                    for item in production_request.get("input", [])
                    if isinstance(item, dict)
                    and item.get("type") == "additional_tools"
                    for tool in item.get("tools", [])
                    if isinstance(tool, dict)
                ]
                production_names = {
                    tool.get("name") or tool.get("type")
                    for tool in additional_tools
                }
                legacy_surface = {
                    "exec",
                    "wait",
                    "list_mcp_resources",
                    "list_mcp_resource_templates",
                    "read_mcp_resource",
                    "update_plan",
                    "request_user_input",
                    "apply_patch",
                    "view_image",
                    "collaboration",
                    "tool_search",
                }
                code_mode_surface = {
                    "exec",
                    "wait",
                    "request_user_input",
                    "collaboration",
                }
                self.assertIn(
                    production_names,
                    (legacy_surface, code_mode_surface),
                )
                self.assertTrue(
                    production_names.isdisjoint(
                        {
                            "exec_command",
                            "write_stdin",
                            "shell",
                            "shell_command",
                            "web_search",
                            "request_plugin_install",
                        }
                    )
                )
                if production_names == legacy_surface:
                    tool_search = next(
                        tool
                        for tool in additional_tools
                        if tool.get("type") == "tool_search"
                    )
                    tool_search_description = str(
                        tool_search.get("description", "")
                    )
                    self.assertIn("ctfos_live", tool_search_description)
                    self.assertNotIn("codex_apps", tool_search_description)
                else:
                    # Codex 0.146 code mode exposes deferred MCP tools only
                    # through the local exec registry.  Keep this an exact
                    # four-tool surface and require the documented registry
                    # boundary rather than accepting an arbitrary subset.
                    exec_tool = next(
                        tool
                        for tool in additional_tools
                        if tool.get("name") == "exec"
                    )
                    exec_description = str(
                        exec_tool.get("description", "")
                    )
                    self.assertIn("ALL_TOOLS", exec_description)
                    self.assertIn("nested tools", exec_description)
                self.assertNotIn(b"mcp__codex_apps__", production_bytes)
                self.assertNotIn(capability.encode("utf-8"), production_bytes)
                self.assertNotIn(str(mailbox).encode("utf-8"), production_bytes)

                schema_path = root / "schema.json"
                schema_path.write_text(
                    json.dumps(role_output_schema(Role.RECON)),
                    encoding="utf-8",
                )
                for model in (
                    ModelCatalog().sol,
                    ModelCatalog().terra,
                    ModelCatalog().luna,
                ):
                    batch = BatchCommandBuilder(executable=codex).build(
                        BatchInvocation(
                            f"review-batch-{model}",
                            Role.RECON,
                            "review tool surface",
                            root,
                            root / f"batch-output-{model}",
                            model_id=model,
                        ),
                        schema_path,
                        root / f"result-{model}.json",
                    )
                    batch_command = [
                        *batch.argv[:-1],
                        *provider_args,
                        "--ephemeral",
                        batch.argv[-1],
                    ]
                    capture_count = len(captured)
                    try:
                        batch_completed = subprocess.run(
                            batch_command,
                            env=environment,
                            input=batch.stdin,
                            capture_output=True,
                            text=True,
                            timeout=20,
                            check=False,
                        )
                    except subprocess.TimeoutExpired as error:
                        self.fail(f"Batch Codex tool capture timed out: {error}")
                    self.assertGreater(
                        len(captured),
                        capture_count,
                        (
                            f"Codex did not send the Batch {model} request; "
                            f"returncode={batch_completed.returncode}, "
                            f"stderr={batch_completed.stderr[-2000:]}"
                        ),
                    )
                    batch_request = json.loads(captured[-1])
                    batch_tools = [
                        tool
                        for tool in batch_request.get("tools", [])
                        if isinstance(tool, dict)
                    ]
                    batch_tools.extend(
                        tool
                        for item in batch_request.get("input", [])
                        if isinstance(item, dict)
                        and item.get("type") == "additional_tools"
                        for tool in item.get("tools", [])
                        if isinstance(tool, dict)
                    )
                    batch_names: set[str] = set()
                    pending_tools = list(batch_tools)
                    while pending_tools:
                        tool = pending_tools.pop()
                        tool_name = tool.get("name") or tool.get("type")
                        if isinstance(tool_name, str):
                            batch_names.add(tool_name)
                        pending_tools.extend(
                            child
                            for child in tool.get("tools", [])
                            if isinstance(child, dict)
                        )
                    self.assertTrue(
                        batch_names.isdisjoint(
                            {
                                "collaboration",
                                "multi_agent_v1",
                                "spawn_agent",
                                "followup_task",
                                "send_message",
                                "wait_agent",
                                "interrupt_agent",
                                "list_agents",
                                "exec_command",
                                "write_stdin",
                                "shell",
                                "shell_command",
                                "web_search",
                                "request_plugin_install",
                            }
                        ),
                        f"unexpected Batch {model} tools: {sorted(batch_names)}",
                    )
                    self.assertNotIn(
                        b"mcp__codex_apps__",
                        captured[-1],
                        f"account app leaked into Batch {model}",
                    )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
            self.assertFalse(server_thread.is_alive())

    def test_live_mcp_executable_must_be_absolute_and_executable(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute path"):
            LiveCommandBuilder(mcp_executable="ctfos-live-mcp")
        with self.assertRaisesRegex(ValueError, "existing executable"):
            LiveCommandBuilder(mcp_executable="/not/a/real/ctfos-python")

    def test_live_start_and_resume_hide_mailbox_and_keep_network_denied(
        self,
    ) -> None:
        runtime = Path("/state/challenges/example/runtime")
        mailbox = runtime / "live-mailboxes" / "session-0123456789abcdef"
        session = LiveSession(
            "live-mailbox",
            Path("/challenge"),
            "solve this",
            broker_directory=mailbox,
        )
        builder = LiveCommandBuilder()

        for command in (
            builder.start(session),
            builder.resume(session, "thread-123"),
        ):
            self.assertNotIn("--add-dir", command.argv)
            self.assertNotIn(str(mailbox), command.argv)
            self.assertNotIn(str(runtime), command.argv)
            self.assertIn(
                "sandbox_workspace_write.network_access=false",
                command.argv,
            )
            self.assertNotIn(
                "sandbox_workspace_write.network_access=true",
                command.argv,
            )
            self.assertFalse(
                any(
                    value.startswith("features.network_proxy.")
                    for value in command.argv
                )
            )


class EventTests(unittest.TestCase):
    def test_jsonl_usage_failure_and_flag_are_streamed_and_deduplicated(self) -> None:
        flags = []
        accumulator = EventAccumulator(on_flag=flags.append)
        accumulator.feed('{"type":"thread.started","thread_id":"thread-1"}\n')
        accumulator.feed(
            '{"type":"item.completed","item":{"type":"command_execution",'
            '"aggregated_output":"answer: WACON{candidate_1}"}}\n'
        )
        accumulator.feed(
            '{"type":"turn.completed","usage":{"input_tokens":10,'
            '"cached_input_tokens":3,"output_tokens":4,"reasoning_output_tokens":2}}\n'
        )
        accumulator.feed(
            '{"type":"error","error":{"code":"rate_limit","message":"temporarily limited"}}\n'
        )
        accumulator.feed("non-json KCTF{candidate_2}\n")
        accumulator.scan_final({"flag_candidates": ["WACON{candidate_1}"]})

        self.assertEqual(accumulator.thread_id, "thread-1")
        self.assertEqual(accumulator.usage.input_tokens, 10)
        self.assertEqual(accumulator.usage.reasoning_output_tokens, 2)
        self.assertTrue(accumulator.failures[0].retryable)
        self.assertEqual(
            [candidate.value for candidate in flags],
            ["WACON{candidate_1}", "KCTF{candidate_2}"],
        )
        self.assertEqual(len(accumulator.malformed_lines), 1)

    def test_event_flag_scanner_ignores_invalid_candidate_without_quota_cost(
        self,
    ) -> None:
        flags = []
        accumulator = EventAccumulator(
            detector=EventFlagDetector(candidate_limit=1),
            on_flag=flags.append,
        )
        accumulator.feed(
            '{"type":"item.completed","text":"KCTF{bad\\tflag}"}\n'
        )
        accumulator.feed(
            '{"type":"item.completed","text":"KCTF{valid_flag}"}\n'
        )

        self.assertEqual(
            [candidate.value for candidate in flags],
            ["KCTF{valid_flag}"],
        )
        self.assertEqual(accumulator.detector.suppressed_matches, 0)

    def test_event_flag_scanner_suppresses_generic_code_noise_only_in_text(
        self,
    ) -> None:
        detector = EventFlagDetector(
            suppress_generic_code_noise=True,
        )

        scanned = detector.scan(
            "body{color:#222;margin:0} "
            "return{file:!1,glob:!1,sortOrder:!1} "
            "DH{%s} DH{real_candidate}",
            "item.completed",
        )
        explicit = detector.report_candidate(
            "body{color:#222;margin:0}",
            "turn.completed",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ["DH{real_candidate}"],
        )
        self.assertIsNotNone(explicit)
        self.assertEqual(
            explicit.value,
            "body{color:#222;margin:0}",
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 3)

    def test_event_code_noise_does_not_hide_later_real_candidate(self) -> None:
        detector = EventFlagDetector(
            candidate_limit=1,
            suppress_generic_code_noise=True,
        )

        scanned = detector.scan(
            ".disabled{color:#ccc} "
            "return{file:!1} "
            "function{return result=1} "
            "KCTF{color:red;margin:0}",
            "item.completed",
            "/challenge/assets/site.css",
        )

        self.assertEqual(
            [candidate.value for candidate in scanned],
            ["KCTF{color:red;margin:0}"],
        )
        self.assertEqual(
            detector.accepted_chars,
            len("KCTF{color:red;margin:0}"),
        )
        self.assertEqual(detector.code_noise_suppressed_matches, 3)
        self.assertEqual(detector.suppressed_matches, 3)

    def test_flag_callback_failure_releases_failed_and_unattempted_values(
        self,
    ) -> None:
        attempts: list[str] = []
        fail_once = True

        def notify(candidate) -> None:
            nonlocal fail_once
            attempts.append(candidate.value)
            if fail_once:
                fail_once = False
                raise OSError("durable candidate notification failed")

        accumulator = EventAccumulator(
            detector=EventFlagDetector(candidate_limit=2),
            on_flag=notify,
        )
        line = json.dumps(
            {
                "type": "item.completed",
                "text": "KCTF{first} KCTF{second}",
            }
        )

        with self.assertRaisesRegex(
            FlagNotificationError,
            "notification failed",
        ):
            accumulator.feed(line)

        self.assertEqual(accumulator.flags, [])
        accumulator.feed(line)
        self.assertEqual(
            attempts,
            ["KCTF{first}", "KCTF{first}", "KCTF{second}"],
        )
        self.assertEqual(
            [candidate.value for candidate in accumulator.flags],
            ["KCTF{first}", "KCTF{second}"],
        )


class LimiterTests(unittest.TestCase):
    def test_slot_acquire_requires_an_installed_cleanup_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            limiters = (
                FifoModelCallLimiter(1),
                FileFifoModelCallLimiter(
                    Path(temporary) / "model-calls.json",
                    1,
                    poll_interval=0.005,
                ),
            )
            for limiter in limiters:
                with (
                    self.subTest(limiter=type(limiter).__name__),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "requires an active with guard",
                    ),
                ):
                    limiter.slot(timeout=0).acquire()
                self.assertEqual(
                    limiter.snapshot(),
                    LimiterSnapshot(1, 0, 0),
                )

    def test_batch_slot_factory_return_interrupt_is_resource_free(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic slot factory return interrupt"),
            SystemExit("synthetic slot factory return exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                limiter = FifoModelCallLimiter(1)
                runner = BatchRunner(limiter=limiter)
                factory_code = runner._model_call_slot.__func__.__code__

                def interrupt_return(
                    frame,
                    event,
                    _argument,
                    target_code=factory_code,
                    target_owner=runner,
                    target_interruption=interruption,
                ):
                    if (
                        frame.f_code is target_code
                        and event == "return"
                        and frame.f_locals.get("self") is target_owner
                    ):
                        raise target_interruption
                    return interrupt_return

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_return)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        with runner._model_call_slot(None) as slot:
                            slot.acquire()
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                self.assertEqual(
                    limiter.snapshot(),
                    LimiterSnapshot(1, 0, 0),
                )

    def test_slot_enter_return_interrupt_acquires_no_capacity(self) -> None:
        for limiter_kind in ("local", "file"):
            for interruption in (
                KeyboardInterrupt("synthetic slot enter return interrupt"),
                SystemExit("synthetic slot enter return exit"),
            ):
                with (
                    self.subTest(
                        limiter=limiter_kind,
                        interruption=type(interruption).__name__,
                    ),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    limiter = (
                        FifoModelCallLimiter(1)
                        if limiter_kind == "local"
                        else FileFifoModelCallLimiter(
                            Path(temporary) / "model-calls.json",
                            1,
                            poll_interval=0.005,
                        )
                    )
                    slot = limiter.slot(timeout=0)
                    enter_code = slot.__enter__.__func__.__code__

                    def interrupt_return(
                        frame,
                        event,
                        _argument,
                        target_code=enter_code,
                        target_owner=slot,
                        target_interruption=interruption,
                    ):
                        if (
                            frame.f_code is target_code
                            and event == "return"
                            and frame.f_locals.get("self") is target_owner
                        ):
                            raise target_interruption
                        return interrupt_return

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_return)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            with slot as guarded_slot:
                                guarded_slot.acquire()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(
                        limiter.snapshot(),
                        LimiterSnapshot(1, 0, 0),
                    )
                    with limiter.slot(timeout=0) as next_slot:
                        next_slot.acquire()
                    self.assertEqual(
                        limiter.snapshot(),
                        LimiterSnapshot(1, 0, 0),
                    )

    def test_slot_acquire_return_interrupt_releases_capacity(self) -> None:
        for limiter_kind in ("local", "file"):
            for interruption in (
                KeyboardInterrupt("synthetic slot acquire return interrupt"),
                SystemExit("synthetic slot acquire return exit"),
            ):
                with (
                    self.subTest(
                        limiter=limiter_kind,
                        interruption=type(interruption).__name__,
                    ),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    limiter = (
                        FifoModelCallLimiter(1)
                        if limiter_kind == "local"
                        else FileFifoModelCallLimiter(
                            Path(temporary) / "model-calls.json",
                            1,
                            poll_interval=0.005,
                        )
                    )
                    slot = limiter.slot(timeout=0)
                    acquire_code = slot.acquire.__func__.__code__

                    def interrupt_return(
                        frame,
                        event,
                        _argument,
                        target_code=acquire_code,
                        target_owner=slot,
                        target_interruption=interruption,
                    ):
                        if (
                            frame.f_code is target_code
                            and event == "return"
                            and frame.f_locals.get("self") is target_owner
                        ):
                            raise target_interruption
                        return interrupt_return

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_return)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            with slot as guarded_slot:
                                guarded_slot.acquire()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(
                        limiter.snapshot(),
                        LimiterSnapshot(1, 0, 0),
                    )
                    with limiter.slot(timeout=0) as next_slot:
                        next_slot.acquire()
                    self.assertEqual(
                        limiter.snapshot(),
                        LimiterSnapshot(1, 0, 0),
                    )

    def test_file_state_lock_acquire_return_interrupt_unlocks(self) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic state lock return interrupt"),
            SystemExit("synthetic state lock return exit"),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as temporary,
            ):
                limiter = FileFifoModelCallLimiter(
                    Path(temporary) / "model-calls.json",
                    1,
                    poll_interval=0.005,
                )
                lock_owner = limiter._locked_state()
                acquire_code = lock_owner.acquire.__func__.__code__

                def interrupt_return(
                    frame,
                    event,
                    _argument,
                    target_code=acquire_code,
                    target_owner=lock_owner,
                    target_interruption=interruption,
                ):
                    if (
                        frame.f_code is target_code
                        and event == "return"
                        and frame.f_locals.get("self") is target_owner
                    ):
                        raise target_interruption
                    return interrupt_return

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_return)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        with lock_owner as guarded_owner:
                            guarded_owner.acquire()
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                completed = threading.Event()

                def inspect_from_another_thread() -> None:
                    limiter.snapshot()
                    completed.set()

                inspector = threading.Thread(
                    target=inspect_from_another_thread
                )
                inspector.start()
                inspector.join(timeout=1)
                self.assertTrue(completed.is_set())
                self.assertFalse(inspector.is_alive())
                self.assertEqual(
                    limiter.snapshot(),
                    LimiterSnapshot(1, 0, 0),
                )

    def test_file_limiter_lock_wait_honors_slot_deadline(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            ready = context.Event()
            blocker = context.Process(
                target=_hold_model_limiter_lock,
                args=(
                    str(state_path.with_suffix(".json.lock")),
                    ready,
                    0.6,
                ),
            )
            blocker.start()
            self.addCleanup(_stop_test_process, blocker)
            self.assertTrue(ready.wait(timeout=1))

            started = time.monotonic()
            with self.assertRaises(
                limiter_module.ModelCallLimitTimeout
            ):
                with limiter.slot(timeout=0.05) as model_call_slot:
                    model_call_slot.acquire()
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 0.3)
            self.assertTrue(blocker.is_alive())
            blocker.join(timeout=1)
            self.assertFalse(blocker.is_alive())
            self.assertEqual(blocker.exitcode, 0)
            self.assertEqual(
                limiter.snapshot(),
                LimiterSnapshot(1, 0, 0),
            )

    def test_local_limiter_mutex_wait_honors_slot_deadline(self) -> None:
        limiter = FifoModelCallLimiter(1)
        started = threading.Event()
        completed = threading.Event()
        failures: list[BaseException] = []
        elapsed: list[float] = []

        def wait_for_slot() -> None:
            began = time.monotonic()
            started.set()
            try:
                with limiter.slot(timeout=0.03) as model_call_slot:
                    model_call_slot.acquire()
            except BaseException as error:
                failures.append(error)
            finally:
                elapsed.append(time.monotonic() - began)
                completed.set()

        limiter._condition.acquire()
        waiter = threading.Thread(target=wait_for_slot)
        try:
            waiter.start()
            self.assertTrue(started.wait(timeout=1))
            self.assertTrue(
                completed.wait(timeout=0.3),
                "local limiter timeout waited for the blocked mutex",
            )
        finally:
            limiter._condition.release()
            waiter.join(timeout=1)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0],
            limiter_module.ModelCallLimitTimeout,
        )
        self.assertLess(elapsed[0], 0.2)
        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )

    def test_file_limiter_rejects_grant_committed_after_deadline(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            limiter = FileFifoModelCallLimiter(
                Path(temporary) / "model-calls.json",
                1,
                poll_interval=0.005,
            )
            real_commit = limiter._commit_state
            commits = 0

            def delay_grant_commit(serialized_before, state):
                nonlocal commits
                commits += 1
                real_commit(serialized_before, state)
                if commits == 2:
                    time.sleep(0.06)

            with (
                mock.patch.object(
                    limiter,
                    "_commit_state",
                    side_effect=delay_grant_commit,
                ),
                self.assertRaises(
                    limiter_module.ModelCallLimitTimeout
                ),
            ):
                with limiter.slot(timeout=0.02) as model_call_slot:
                    model_call_slot.acquire()

            self.assertGreaterEqual(commits, 3)
            self.assertEqual(
                limiter.snapshot(),
                LimiterSnapshot(1, 0, 0),
            )

    def test_local_cleanup_control_supersedes_active_timeout(self) -> None:
        limiter = FifoModelCallLimiter(1)
        held = limiter.slot(timeout=0)
        held.__enter__()
        held.acquire()
        real_release = limiter._condition.release
        interruption = KeyboardInterrupt(
            "synthetic condition cleanup control"
        )
        release_calls = 0

        def interrupt_release_retry():
            nonlocal release_calls
            release_calls += 1
            if release_calls == 1:
                raise OSError("synthetic condition cleanup failure")
            if release_calls == 2:
                raise interruption
            return real_release()

        limiter._condition.release = interrupt_release_retry
        try:
            with self.assertRaises(KeyboardInterrupt) as raised:
                with limiter.slot(timeout=0) as model_call_slot:
                    model_call_slot.acquire()
            self.assertIs(raised.exception, interruption)
        finally:
            limiter._condition.release = real_release
            held.__exit__(None, None, None)

        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )

    def test_file_commit_cleanup_control_supersedes_write_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            limiter = FileFifoModelCallLimiter(
                Path(temporary) / "model-calls.json",
                1,
            )
            interruption = KeyboardInterrupt(
                "synthetic shared commit cleanup control"
            )
            state = {
                "version": 1,
                "capacity": 1,
                "queue": [],
                "holders": [],
            }

            with (
                mock.patch.object(
                    Path,
                    "open",
                    side_effect=OSError("synthetic shared commit failure"),
                ),
                mock.patch.object(
                    Path,
                    "unlink",
                    side_effect=interruption,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                limiter._commit_state(None, state)

            self.assertIs(raised.exception, interruption)

    def test_local_limiter_cleanup_acquire_handoff_releases_rlock(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)
        interruption = KeyboardInterrupt(
            "synthetic condition acquire handoff interrupt"
        )
        real_acquire = limiter._condition.acquire
        acquire_calls = 0

        def acquire_then_interrupt(*args, **kwargs):
            nonlocal acquire_calls
            acquire_calls += 1
            result = real_acquire(*args, **kwargs)
            if acquire_calls == 2:
                raise interruption
            return result

        limiter._condition.acquire = acquire_then_interrupt
        with self.assertRaises(KeyboardInterrupt) as raised:
            with limiter.slot(timeout=0) as model_call_slot:
                model_call_slot.acquire()
                pass
        self.assertIs(raised.exception, interruption)

        completed = threading.Event()

        def inspect_from_another_thread() -> None:
            limiter.snapshot()
            completed.set()

        inspector = threading.Thread(target=inspect_from_another_thread)
        inspector.start()
        inspector.join(timeout=1)
        self.assertTrue(completed.is_set())
        self.assertFalse(inspector.is_alive())
        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )

    def test_local_limiter_release_interrupt_retries_rlock(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)
        interruption = KeyboardInterrupt(
            "synthetic condition release interrupt"
        )
        real_release = limiter._condition.release
        release_calls = 0

        def release_then_interrupt():
            nonlocal release_calls
            release_calls += 1
            if release_calls == 1:
                raise interruption
            return real_release()

        limiter._condition.release = release_then_interrupt
        with self.assertRaises(KeyboardInterrupt) as raised:
            with limiter.slot(timeout=0) as model_call_slot:
                model_call_slot.acquire()
                pass
        self.assertIs(raised.exception, interruption)
        self.assertGreaterEqual(release_calls, 3)

        completed = threading.Event()

        def inspect_from_another_thread() -> None:
            limiter.snapshot()
            completed.set()

        inspector = threading.Thread(target=inspect_from_another_thread)
        inspector.start()
        inspector.join(timeout=1)
        self.assertTrue(completed.is_set())
        self.assertFalse(inspector.is_alive())
        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )

    def test_local_limiter_transient_cleanup_error_is_retried(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)

        class FailingDiscardSet(set):
            failed = False

            def discard(self, value):
                if not self.failed:
                    self.failed = True
                    raise OSError("synthetic transient holder cleanup error")
                super().discard(value)

        limiter._holders = FailingDiscardSet()
        with limiter.slot(timeout=0) as model_call_slot:
            model_call_slot.acquire()
            pass
        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )
        with limiter.slot(timeout=0) as model_call_slot:
            model_call_slot.acquire()
            pass

    def test_local_limiter_cleanup_interrupt_retries_and_propagates(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)
        interruption = KeyboardInterrupt(
            "synthetic local holder cleanup interrupt"
        )

        class InterruptingDiscardSet(set):
            interrupted = False

            def discard(self, value):
                if not self.interrupted:
                    self.interrupted = True
                    raise interruption
                super().discard(value)

        limiter._holders = InterruptingDiscardSet()
        with self.assertRaises(KeyboardInterrupt) as raised:
            with limiter.slot(timeout=0) as model_call_slot:
                model_call_slot.acquire()
                pass

        self.assertIs(raised.exception, interruption)
        self.assertEqual(
            limiter.snapshot(),
            LimiterSnapshot(1, 0, 0),
        )
        with limiter.slot(timeout=0) as model_call_slot:
            model_call_slot.acquire()
            pass

    def test_local_limiter_interrupts_leave_no_ticket_or_holder(
        self,
    ) -> None:
        for stage in ("append", "pop", "holder"):
            with self.subTest(stage=stage):
                limiter = FifoModelCallLimiter(1)
                interruption = KeyboardInterrupt(
                    f"synthetic local limiter {stage} interrupt"
                )

                if stage == "append":
                    class InterruptingAppendQueue(deque):
                        def append(self, value):
                            super().append(value)
                            raise interruption

                    limiter._queue = InterruptingAppendQueue()
                elif stage == "pop":
                    class InterruptingPopQueue(deque):
                        def popleft(self):
                            super().popleft()
                            raise interruption

                    limiter._queue = InterruptingPopQueue()
                else:
                    class InterruptingHolders(set):
                        def add(self, value):
                            super().add(value)
                            raise interruption

                    limiter._holders = InterruptingHolders()

                with self.assertRaises(KeyboardInterrupt) as raised:
                    with limiter.slot(timeout=0) as model_call_slot:
                        model_call_slot.acquire()
                        raise AssertionError(
                            "interrupted limiter unexpectedly acquired"
                        )
                self.assertIs(raised.exception, interruption)
                self.assertEqual(
                    limiter.snapshot(),
                    LimiterSnapshot(1, 0, 0),
                )

    def test_file_limiter_interrupts_remove_persisted_ticket(
        self,
    ) -> None:
        for interrupt_call in (1, 2):
            with self.subTest(interrupt_call=interrupt_call):
                with tempfile.TemporaryDirectory() as temporary:
                    state_path = (
                        Path(temporary) / "model-calls.json"
                    )
                    limiter = FileFifoModelCallLimiter(
                        state_path,
                        1,
                        poll_interval=0.005,
                    )
                    real_locked_state = limiter._with_locked_state
                    interruption = KeyboardInterrupt(
                        "synthetic persisted limiter interrupt"
                    )
                    calls = 0

                    def interrupt_after_persist(operation, **lock_options):
                        nonlocal calls
                        calls += 1
                        current_call = calls
                        result = real_locked_state(
                            operation,
                            **lock_options,
                        )
                        if current_call == interrupt_call:
                            raise interruption
                        return result

                    limiter._with_locked_state = interrupt_after_persist
                    with self.assertRaises(
                        KeyboardInterrupt
                    ) as raised:
                        with limiter.slot(timeout=1) as model_call_slot:
                            model_call_slot.acquire()
                            raise AssertionError(
                                "interrupted shared limiter acquired"
                            )
                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(
                        limiter.snapshot(),
                        LimiterSnapshot(1, 0, 0),
                    )
                    self.assertEqual(
                        list(
                            state_path.parent.glob(
                                f".{state_path.name}.*.tmp"
                            )
                        ),
                        [],
                    )

    def test_file_limiter_cleanup_interrupt_retries_and_propagates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            real_replace = limiter_module.os.replace
            interruption = KeyboardInterrupt(
                "synthetic shared holder cleanup interrupt"
            )
            state_replaces = 0

            def interrupt_cleanup_replace(source, destination):
                nonlocal state_replaces
                if Path(destination) == state_path:
                    state_replaces += 1
                    if state_replaces == 3:
                        raise interruption
                return real_replace(source, destination)

            with (
                mock.patch.object(
                    limiter_module.os,
                    "replace",
                    side_effect=interrupt_cleanup_replace,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                with limiter.slot(timeout=0) as model_call_slot:
                    model_call_slot.acquire()
                    pass

            self.assertIs(raised.exception, interruption)
            self.assertGreaterEqual(state_replaces, 4)
            self.assertEqual(
                limiter.snapshot(),
                LimiterSnapshot(1, 0, 0),
            )
            with limiter.slot(timeout=0) as model_call_slot:
                model_call_slot.acquire()
                pass

    def test_file_limiter_transient_cleanup_error_is_retried(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            real_replace = limiter_module.os.replace
            state_replaces = 0

            def fail_cleanup_replace_once(source, destination):
                nonlocal state_replaces
                if Path(destination) == state_path:
                    state_replaces += 1
                    if state_replaces == 3:
                        raise OSError(
                            "synthetic transient holder cleanup error"
                        )
                return real_replace(source, destination)

            with mock.patch.object(
                limiter_module.os,
                "replace",
                side_effect=fail_cleanup_replace_once,
            ):
                with limiter.slot(timeout=0) as model_call_slot:
                    model_call_slot.acquire()
                    pass

            self.assertGreaterEqual(state_replaces, 4)
            self.assertEqual(
                limiter.snapshot(),
                LimiterSnapshot(1, 0, 0),
            )
            with limiter.slot(timeout=0) as model_call_slot:
                model_call_slot.acquire()
                pass

    def test_local_limiter_is_fifo(self) -> None:
        limiter = FifoModelCallLimiter(1)
        order: list[int] = []

        def acquire(number: int) -> None:
            with limiter.slot(timeout=2) as model_call_slot:
                model_call_slot.acquire()
                order.append(number)

        with limiter.slot() as model_call_slot:
            model_call_slot.acquire()
            first = threading.Thread(target=acquire, args=(1,))
            first.start()
            deadline = time.monotonic() + 1
            while limiter.snapshot().waiting < 1 and time.monotonic() < deadline:
                time.sleep(0.005)
            second = threading.Thread(target=acquire, args=(2,))
            second.start()
            deadline = time.monotonic() + 1
            while limiter.snapshot().waiting < 2 and time.monotonic() < deadline:
                time.sleep(0.005)
        first.join(2)
        second.join(2)
        self.assertEqual(order, [1, 2])
        self.assertEqual(limiter.snapshot().active, 0)

    def test_local_limiter_cancellation_removes_its_existing_ticket(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)
        cancel_event = threading.Event()
        cancellations: list[str] = []

        def wait() -> None:
            try:
                with limiter.slot(
                    timeout=2,
                    cancel_event=cancel_event,
                ) as model_call_slot:
                    model_call_slot.acquire()
                    raise AssertionError("cancelled local waiter acquired")
            except RuntimeError as error:
                cancellations.append(str(error))

        with limiter.slot() as model_call_slot:
            model_call_slot.acquire()
            waiter = threading.Thread(target=wait)
            waiter.start()
            deadline = time.monotonic() + 1
            while (
                limiter.snapshot().waiting < 1
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            self.assertEqual(limiter.snapshot().waiting, 1)
            cancel_event.set()
            waiter.join(timeout=1)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(limiter.snapshot().waiting, 0)

        self.assertEqual(len(cancellations), 1)
        self.assertIn("cancel", cancellations[0])
        self.assertEqual(limiter.snapshot().active, 0)

    def test_file_limiter_records_start_ticks_and_removes_reused_pid_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(state_path, 1, poll_interval=0.005)
            with limiter.slot(timeout=1) as model_call_slot:
                model_call_slot.acquire()
                state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(len(state["holders"]), 1)
                self.assertIsInstance(state["holders"][0]["process_start_ticks"], int)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["holders"], [])
            state["holders"] = [
                {
                    "ticket": "reused",
                    "pid": os.getpid(),
                    "process_start_ticks": -1,
                    "started_at": time.time(),
                }
            ]
            state_path.write_text(json.dumps(state), encoding="utf-8")
            self.assertEqual(limiter.snapshot().active, 0)

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").exists(),
        "requires Linux processes",
    )
    def test_file_limiter_is_fifo_across_three_processes(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            result_queue = context.Queue()
            releases = [context.Event() for _ in range(3)]
            processes = [
                context.Process(
                    target=_file_limiter_worker,
                    args=(
                        str(state_path),
                        number,
                        releases[number],
                        result_queue,
                    ),
                )
                for number in range(3)
            ]
            try:
                processes[0].start()
                self.assertEqual(
                    result_queue.get(timeout=2)[:2],
                    ("acquired", 0),
                )

                processes[1].start()
                _wait_file_limiter_state(
                    state_path,
                    active=1,
                    waiting=1,
                )
                processes[2].start()
                _wait_file_limiter_state(
                    state_path,
                    active=1,
                    waiting=2,
                )

                releases[0].set()
                self.assertEqual(
                    result_queue.get(timeout=2)[:2],
                    ("acquired", 1),
                )
                releases[1].set()
                self.assertEqual(
                    result_queue.get(timeout=2)[:2],
                    ("acquired", 2),
                )
                releases[2].set()
            finally:
                for release in releases:
                    release.set()
                for process in processes:
                    if process.pid is None:
                        continue
                    process.join(timeout=2)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=2)

            self.assertEqual(
                [process.exitcode for process in processes],
                [0, 0, 0],
            )
            state = _wait_file_limiter_state(
                state_path,
                active=0,
                waiting=0,
            )
            self.assertEqual(state["queue"], [])
            self.assertEqual(state["holders"], [])

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").exists(),
        "requires Linux processes",
    )
    def test_file_limiter_cancels_middle_process_without_reordering_tail(
        self,
    ) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            result_queue = context.Queue()
            middle_cancel = context.Event()
            middle_release = context.Event()
            tail_release = context.Event()
            middle = context.Process(
                target=_file_limiter_worker,
                args=(
                    str(state_path),
                    1,
                    middle_release,
                    result_queue,
                    middle_cancel,
                ),
            )
            tail = context.Process(
                target=_file_limiter_worker,
                args=(
                    str(state_path),
                    2,
                    tail_release,
                    result_queue,
                ),
            )
            try:
                with limiter.slot(timeout=1) as model_call_slot:
                    model_call_slot.acquire()
                    middle.start()
                    _wait_file_limiter_state(
                        state_path,
                        active=1,
                        waiting=1,
                    )
                    tail.start()
                    queued = _wait_file_limiter_state(
                        state_path,
                        active=1,
                        waiting=2,
                    )
                    tail_ticket = queued["queue"][1]["ticket"]

                    cancelled_at = time.monotonic()
                    middle_cancel.set()
                    cancelled = result_queue.get(timeout=2)
                    self.assertEqual(cancelled[:2], ("cancelled", 1))
                    self.assertIn("cancel", cancelled[3])
                    self.assertLess(
                        time.monotonic() - cancelled_at,
                        0.5,
                    )
                    remaining = _wait_file_limiter_state(
                        state_path,
                        active=1,
                        waiting=1,
                    )
                    self.assertEqual(
                        remaining["queue"][0]["ticket"],
                        tail_ticket,
                    )

                self.assertEqual(
                    result_queue.get(timeout=2)[:2],
                    ("acquired", 2),
                )
                tail_release.set()
            finally:
                middle_cancel.set()
                middle_release.set()
                tail_release.set()
                for process in (middle, tail):
                    if process.pid is None:
                        continue
                    process.join(timeout=2)
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=2)

            self.assertEqual(middle.exitcode, 0)
            self.assertEqual(tail.exitcode, 0)
            _wait_file_limiter_state(
                state_path,
                active=0,
                waiting=0,
            )

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").exists(),
        "requires Linux processes",
    )
    def test_file_limiter_reclaims_a_dead_holder_process(self) -> None:
        context = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "model-calls.json"
            acquired = context.Event()
            process = context.Process(
                target=_file_limiter_acquire_then_die,
                args=(str(state_path), acquired),
            )
            process.start()
            self.assertTrue(acquired.wait(timeout=2))
            process.join(timeout=2)
            self.assertEqual(process.exitcode, 0)
            persisted = json.loads(
                state_path.read_text(encoding="utf-8")
            )
            self.assertEqual(len(persisted["holders"]), 1)

            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            self.assertEqual(limiter.snapshot().active, 0)
            with limiter.slot(timeout=1) as model_call_slot:
                model_call_slot.acquire()
                self.assertEqual(limiter.snapshot().active, 1)
            self.assertEqual(limiter.snapshot().active, 0)


class BatchRunnerTests(unittest.TestCase):
    def test_runner_rejects_nonfinite_wait_and_process_bounds(self) -> None:
        invalid = (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
        )
        for value in invalid:
            with (
                self.subTest(bound="limiter_wait_timeout", value=value),
                self.assertRaisesRegex(
                    ValueError,
                    "limiter_wait_timeout must be positive and finite",
                ),
            ):
                BatchRunner(limiter_wait_timeout=value)
            with (
                self.subTest(bound="terminate_grace_seconds", value=value),
                self.assertRaisesRegex(
                    ValueError,
                    "terminate_grace_seconds must be positive and finite",
                ),
            ):
                SubprocessExecutor(terminate_grace_seconds=value)
            with (
                self.subTest(bound="drain_grace_seconds", value=value),
                self.assertRaisesRegex(
                    ValueError,
                    "drain_grace_seconds must be positive and finite",
                ),
            ):
                SubprocessExecutor(drain_grace_seconds=value)

        executor = SubprocessExecutor()
        for value in invalid:
            with (
                self.subTest(bound="process_timeout", value=value),
                mock.patch.object(
                    runner_module,
                    "_popen_with_constructor_cleanup",
                ) as popen,
                self.assertRaisesRegex(
                    ValueError,
                    "process timeout must be positive and finite",
                ),
            ):
                executor.run(
                    BuiltCommand(("unused",), ""),
                    cwd=Path.cwd(),
                    timeout=value,
                    on_stdout_line=lambda _line: None,
                )
            popen.assert_not_called()

    def test_stdout_finish_cannot_mask_provider_acquire_control(self) -> None:
        class InterruptingSlot:
            def __init__(self, error: BaseException) -> None:
                self.error = error

            def __enter__(self):
                return self

            def acquire(self) -> float:
                raise self.error

            def __exit__(self, _error_type, _error, _traceback) -> None:
                return None

        class InterruptingLimiter:
            def __init__(self, error: BaseException) -> None:
                self.error = error

            def slot(self, _timeout=None, *, cancel_event=None):
                del cancel_event
                return InterruptingSlot(self.error)

        cases = (
            (
                KeyboardInterrupt("provider acquire interrupt"),
                OSError("capture finish failed"),
            ),
            (
                SystemExit("provider acquire exit"),
                FlagNotificationError("capture notification failed"),
            ),
            (
                KeyboardInterrupt("first control"),
                SystemExit("second control"),
            ),
        )
        for primary, finish_error in cases:
            with self.subTest(
                primary=type(primary).__name__,
                finish=type(finish_error).__name__,
            ):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    with (
                        mock.patch.object(
                            runner_module._BatchStdoutCapture,
                            "finish",
                            side_effect=finish_error,
                        ),
                        self.assertRaises(type(primary)) as raised,
                    ):
                        BatchRunner(
                            limiter=InterruptingLimiter(primary),
                            max_schema_retries=0,
                        ).run(
                            BatchInvocation(
                                "capture-control-priority",
                                Role.RECON,
                                "inspect",
                                root,
                                root / "run",
                            )
                        )

                self.assertIs(raised.exception, primary)
                self.assertTrue(
                    any(
                        "batch stdout capture finalization failed" in note
                        for note in getattr(primary, "__notes__", ())
                    )
                )

    def test_stdout_finish_preserves_its_notification_without_active_error(
        self,
    ) -> None:
        finish_error = FlagNotificationError("capture notification failed")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                mock.patch.object(
                    runner_module._BatchStdoutCapture,
                    "finish",
                    side_effect=finish_error,
                ),
                self.assertRaises(FlagNotificationError) as raised,
            ):
                BatchRunner(
                    process_executor=ScriptedExecutor(
                        [([], valid_payload(Role.RECON), 0)]
                    ),
                    max_schema_retries=0,
                ).run(
                    BatchInvocation(
                        "capture-notification",
                        Role.RECON,
                        "inspect",
                        root,
                        root / "run",
                    )
                )

        self.assertIs(raised.exception, finish_error)

    def test_stdout_finish_ignores_an_inherited_exception_context(self) -> None:
        outer_error = ValueError("caller is handling this")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                raise outer_error
            except ValueError:
                with mock.patch.object(
                    runner_module._BatchStdoutCapture,
                    "finish",
                    side_effect=OSError("capture finish failed"),
                ):
                    result = BatchRunner(
                        process_executor=ScriptedExecutor(
                            [([], valid_payload(Role.RECON), 0)]
                        ),
                        max_schema_retries=0,
                    ).run(
                        BatchInvocation(
                            "capture-inherited-context",
                            Role.RECON,
                            "inspect",
                            root,
                            root / "run",
                        )
                    )

        self.assertFalse(result.success)
        self.assertEqual(result.failures[0].kind, "process_error")
        self.assertIn("capture finish failed", result.failures[0].message)

    def test_unterminated_event_control_survives_finish_flush_and_close(
        self,
    ) -> None:
        class FailingAttemptHandle:
            def __init__(self, delegate) -> None:
                self.delegate = delegate
                self.flush_calls = 0

            def write(self, data):
                return self.delegate.write(data)

            def flush(self) -> None:
                self.flush_calls += 1
                self.delegate.flush()
                if self.flush_calls == 2:
                    raise OSError("finish flush failed")

            def close(self) -> None:
                self.delegate.close()
                raise OSError("raw close failed")

        class UnterminatedEventExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del cwd, timeout
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "thread.started",
                            "thread_id": "unterminated-event",
                        }
                    ).encode("utf-8")
                )
                _output_path(command).write_text(
                    json.dumps(valid_payload(Role.RECON)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.0)

        real_open = Path.open

        def failing_attempt_open(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            mode = args[0] if args else kwargs.get("mode", "r")
            if path.name == "attempt-1.jsonl" and mode == "wb":
                return FailingAttemptHandle(handle)
            return handle

        for primary in (
            KeyboardInterrupt("event callback interrupt"),
            FlagNotificationError("event callback notification failed"),
        ):
            with self.subTest(primary=type(primary).__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)

                    def fail_event(_event) -> None:
                        raise primary

                    with (
                        mock.patch.object(
                            Path,
                            "open",
                            new=failing_attempt_open,
                        ),
                        self.assertRaises(type(primary)) as raised,
                    ):
                        BatchRunner(
                            process_executor=UnterminatedEventExecutor(),
                            max_schema_retries=0,
                        ).run(
                            BatchInvocation(
                                "capture-final-cleanup",
                                Role.RECON,
                                "inspect",
                                root,
                                root / "run",
                            ),
                            on_event=fail_event,
                        )

                self.assertIs(raised.exception, primary)
                notes = getattr(primary, "__notes__", ())
                self.assertTrue(
                    any("final flush failed" in note for note in notes)
                )
                self.assertTrue(
                    any("raw stream close failed" in note for note in notes)
                )

    def test_wave_preserves_provider_control_across_finish_and_close_failures(
        self,
    ) -> None:
        class InterruptingSlot:
            def __init__(self, error: BaseException) -> None:
                self.error = error

            def __enter__(self):
                return self

            def acquire(self) -> float:
                raise self.error

            def __exit__(self, _error_type, _error, _traceback) -> None:
                return None

        class InterruptingLimiter:
            def __init__(self, error: BaseException) -> None:
                self.error = error

            def slot(self, _timeout=None, *, cancel_event=None):
                del cancel_event
                return InterruptingSlot(self.error)

        class FailingCloseHandle:
            def __init__(self, delegate) -> None:
                self.delegate = delegate

            def write(self, data):
                return self.delegate.write(data)

            def flush(self) -> None:
                self.delegate.flush()

            def close(self) -> None:
                self.delegate.close()
                raise OSError("raw close failed")

        real_open = Path.open

        def failing_close_open(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            mode = args[0] if args else kwargs.get("mode", "r")
            if path.name == "attempt-1.jsonl" and mode == "wb":
                return FailingCloseHandle(handle)
            return handle

        for primary in (
            KeyboardInterrupt("wave provider interrupt"),
            FlagNotificationError("wave provider notification failed"),
        ):
            with self.subTest(primary=type(primary).__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    invocation = BatchInvocation(
                        "wave-capture-cleanup",
                        Role.RECON,
                        "inspect",
                        root,
                        root / "run",
                    )
                    with (
                        mock.patch.object(
                            Path,
                            "open",
                            new=failing_close_open,
                        ),
                        mock.patch.object(
                            runner_module._BatchStdoutCapture,
                            "finish",
                            side_effect=OSError("capture finish failed"),
                        ),
                        self.assertRaises(type(primary)) as raised,
                    ):
                        BatchWaveRunner(
                            BatchRunner(
                                limiter=InterruptingLimiter(primary),
                                max_schema_retries=0,
                            )
                        ).run(
                            BatchWave.create(
                                "wave-capture-cleanup",
                                (invocation,),
                            )
                        )

                self.assertIs(raised.exception, primary)
                notes = getattr(primary, "__notes__", ())
                self.assertTrue(
                    any(
                        "capture finalization failed" in note
                        for note in notes
                    )
                )
                self.assertTrue(
                    any("raw stream close failed" in note for note in notes)
                )

    def test_structured_candidate_outside_regex_is_notified_and_retained(
        self,
    ) -> None:
        candidate = "KCTF{" + "x" * 513 + "}"
        executor = ScriptedExecutor(
            [([], valid_payload(Role.RECON, flag=candidate), 0)]
        )
        notified = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "structured-candidate",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                ),
                on_flag=notified.append,
            )

        self.assertTrue(result.success, result.validation.errors)
        self.assertEqual(
            [item.value for item in notified],
            [candidate],
        )
        self.assertEqual(
            [item.value for item in result.flag_candidates],
            [candidate],
        )

    def test_structured_candidate_notification_failure_is_fatal(
        self,
    ) -> None:
        candidate = "KCTF{" + "y" * 513 + "}"
        executor = ScriptedExecutor(
            [([], valid_payload(Role.RECON, flag=candidate), 0)]
        )

        def fail_notification(_candidate) -> None:
            raise OSError("structured terminal unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                FlagNotificationError,
                "terminal unavailable",
            ):
                BatchRunner(
                    process_executor=executor,
                    max_schema_retries=0,
                ).run(
                    BatchInvocation(
                        "structured-notification-failure",
                        Role.RECON,
                        "inspect",
                        root,
                        root / "run",
                    ),
                    on_flag=fail_notification,
                )

    def test_wave_does_not_contain_raw_flag_notification_failure(
        self,
    ) -> None:
        executor = ScriptedExecutor(
            [
                (
                    [
                        {
                            "type": "item.completed",
                            "text": "KCTF{raw_one} KCTF{raw_two}",
                        }
                    ],
                    valid_payload(Role.RECON),
                    0,
                )
            ]
        )

        def fail_notification(_candidate) -> None:
            raise OSError("intent journal unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocation = BatchInvocation(
                "raw-notification-failure",
                Role.RECON,
                "inspect",
                root,
                root / "run",
            )
            with self.assertRaisesRegex(
                FlagNotificationError,
                "intent journal unavailable",
            ):
                BatchWaveRunner(
                    BatchRunner(
                        process_executor=executor,
                        max_schema_retries=0,
                    )
                ).run(
                    BatchWave.create("fatal-notification", (invocation,)),
                    on_flag=fail_notification,
                )

    def test_subprocess_flag_notification_failure_is_not_contained(
        self,
    ) -> None:
        class FlagCommandBuilder:
            def build(
                self,
                invocation,
                schema_path,
                output_path,
                **kwargs,
            ):
                del invocation, schema_path, output_path, kwargs
                script = (
                    "import json,time;"
                    "print(json.dumps({"
                    "'type':'item.completed',"
                    "'text':'KCTF{subprocess_notification}'"
                    "}),flush=True);"
                    "time.sleep(30)"
                )
                return BuiltCommand((sys.executable, "-c", script), "")

        def fail_notification(_candidate) -> None:
            raise OSError("subprocess notification failed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                FlagNotificationError,
                "subprocess notification failed",
            ):
                BatchRunner(
                    command_builder=FlagCommandBuilder(),
                    process_executor=SubprocessExecutor(
                        terminate_grace_seconds=0.1,
                        drain_grace_seconds=0.1,
                    ),
                    max_schema_retries=0,
                ).run(
                    BatchInvocation(
                        "subprocess-notification-failure",
                        Role.RECON,
                        "inspect",
                        root,
                        root / "run",
                        timeout_seconds=2,
                    ),
                    on_flag=fail_notification,
                )

    def test_runner_caps_raw_streams_and_scans_flags_beyond_raw_prefix(self) -> None:
        class OverflowExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del cwd, timeout
                on_stdout_line(b"x" * 40)
                on_stdout_line(b" WAC")
                on_stdout_line(b"ON{rolling_candidate}\n")
                _output_path(command).write_text(
                    json.dumps(valid_payload(Role.RECON)), encoding="utf-8"
                )
                return ProcessOutcome(
                    0,
                    "e" * 40,
                    0.0,
                    stderr_bytes=40,
                    stderr_truncated=False,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=OverflowExecutor(),
                max_schema_retries=0,
                raw_jsonl_limit_bytes=16,
                stderr_limit_bytes=12,
                event_line_limit_bytes=8,
                flag_scan_chunk_chars=8,
                flag_scan_overlap_chars=64,
            ).run(
                BatchInvocation(
                    "bounded-output", Role.RECON, "inspect", root, root / "run"
                )
            )

            attempt = result.attempts[0]
            metadata = json.loads(
                attempt.capture_metadata_path.read_text(encoding="utf-8")
            )
            self.assertTrue(result.success, result.validation.errors)
            self.assertEqual(attempt.raw_jsonl_path.stat().st_size, 16)
            self.assertEqual(attempt.raw_jsonl_bytes, 66)
            self.assertTrue(attempt.raw_jsonl_truncated)
            self.assertEqual(attempt.stderr_path.stat().st_size, 12)
            self.assertEqual(attempt.stderr_bytes, 40)
            self.assertTrue(attempt.stderr_truncated)
            self.assertEqual(
                [candidate.value for candidate in result.flag_candidates],
                ["WACON{rolling_candidate}"],
            )
            self.assertEqual(metadata["stdout_jsonl"]["stored_bytes"], 16)
            self.assertTrue(metadata["stdout_jsonl"]["truncated"])
            self.assertEqual(metadata["stderr"]["stored_bytes"], 12)
            self.assertTrue(metadata["stderr"]["truncated"])

    def test_runner_rejects_oversized_structured_output_without_reading_it(self) -> None:
        output = valid_payload(Role.RECON)
        output["summary"] = "z" * 4096
        executor = ScriptedExecutor([([], output, 0)])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
                structured_output_limit_bytes=256,
            ).run(
                BatchInvocation(
                    "oversized-result", Role.RECON, "inspect", root, root / "run"
                )
            )

            attempt = result.attempts[0]
            metadata = json.loads(
                attempt.capture_metadata_path.read_text(encoding="utf-8")
            )
            self.assertFalse(result.success)
            self.assertTrue(attempt.output_oversized)
            self.assertGreater(attempt.output_bytes or 0, 256)
            self.assertIn("exceeds 256 byte limit", result.validation.errors[0])
            self.assertTrue(metadata["structured_output"]["oversized"])

    def test_incomplete_pipe_capture_is_explicit_and_fails_the_attempt(
        self,
    ) -> None:
        class IncompleteExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del cwd, timeout, on_stdout_line
                _output_path(command).write_text(
                    json.dumps(valid_payload(Role.RECON)),
                    encoding="utf-8",
                )
                return ProcessOutcome(
                    125,
                    "",
                    0.2,
                    stdout_capture_complete=False,
                    stderr_capture_complete=False,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=IncompleteExecutor(),
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "incomplete-capture",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                )
            )

            metadata = json.loads(
                result.attempts[0].capture_metadata_path.read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(result.success)
            self.assertEqual(
                result.failures[0].kind,
                "process_output_incomplete",
            )
            self.assertFalse(
                metadata["stdout_jsonl"]["capture_complete"]
            )
            self.assertFalse(metadata["stderr"]["capture_complete"])
            self.assertIsNone(metadata["stdout_jsonl"]["truncated"])
            self.assertIsNone(metadata["stderr"]["truncated"])

    def test_stdout_callback_error_is_contained_once_and_marks_capture_unknown(
        self,
    ) -> None:
        class CallbackCommandBuilder:
            def build(
                self,
                invocation,
                schema_path,
                output_path,
                **kwargs,
            ):
                del invocation, schema_path, output_path, kwargs
                script = (
                    "import json,time;"
                    "print(json.dumps({"
                    "'type':'thread.started','thread_id':'callback-thread'"
                    "}),flush=True);"
                    "time.sleep(30)"
                )
                return BuiltCommand((sys.executable, "-c", script), "")

        callback_calls = 0

        def fail_callback(_event) -> None:
            nonlocal callback_calls
            callback_calls += 1
            raise RuntimeError("callback exploded")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                command_builder=CallbackCommandBuilder(),
                process_executor=SubprocessExecutor(
                    terminate_grace_seconds=0.1,
                    drain_grace_seconds=0.1,
                ),
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "callback-error",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                    timeout_seconds=2,
                ),
                on_event=fail_callback,
            )

            metadata = json.loads(
                result.attempts[0].capture_metadata_path.read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(callback_calls, 1)
        self.assertFalse(result.success)
        self.assertEqual(
            [failure.kind for failure in result.failures],
            ["process_error"],
        )
        self.assertIn("RuntimeError: callback exploded", result.failures[0].message)
        self.assertNotEqual(result.attempts[0].returncode, 0)
        self.assertFalse(metadata["stdout_jsonl"]["capture_complete"])
        self.assertFalse(metadata["stdout_jsonl"]["truncation_known"])
        self.assertIsNone(metadata["stdout_jsonl"]["truncated"])

    def test_flag_candidate_and_event_collections_have_explicit_caps(self) -> None:
        events = [
            {
                "type": "item.completed",
                "text": f"WACON{{candidate_{number}}}",
            }
            for number in range(6)
        ]
        executor = ScriptedExecutor(
            [(events, valid_payload(Role.RECON), 0)]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
                flag_candidate_limit=2,
                flag_candidate_chars_limit=1024,
                event_count_limit=2,
            ).run(
                BatchInvocation(
                    "bounded-events", Role.RECON, "inspect", root, root / "run"
                )
            )

            attempt = result.attempts[0]
            metadata = json.loads(
                attempt.capture_metadata_path.read_text(encoding="utf-8")
            )
            self.assertEqual(len(result.flag_candidates), 2)
            self.assertEqual(len(result.events), 2)
            self.assertEqual(metadata["event_accumulator"]["events_dropped"], 4)
            self.assertGreater(metadata["flag_scan"]["suppressed_matches"], 0)

    def test_runner_retries_invalid_schema_on_same_thread_and_streams_flag(self) -> None:
        first_output = valid_payload(Role.RECON)
        first_output["unexpected"] = "reject me"
        second_output = valid_payload(Role.RECON, flag="WACON{candidate_1}")
        executor = ScriptedExecutor(
            [
                (
                    [
                        {"type": "thread.started", "thread_id": "thread-1"},
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "agent_message",
                                "text": "possible WACON{candidate_1}",
                            },
                        },
                    ],
                    first_output,
                    0,
                ),
                (
                    [
                        {
                            "type": "turn.completed",
                            "usage": {
                                "input_tokens": 20,
                                "cached_input_tokens": 5,
                                "output_tokens": 8,
                                "reasoning_output_tokens": 3,
                            },
                        }
                    ],
                    second_output,
                    0,
                ),
            ]
        )
        flags = []
        provider_start_checks: list[int] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocation = BatchInvocation(
                "recon-1", Role.RECON, "inspect", root, root / "run"
            )
            result = BatchRunner(
                process_executor=executor, max_schema_retries=1
            ).run(
                invocation,
                on_flag=flags.append,
                before_provider_start=lambda: provider_start_checks.append(
                    len(executor.commands)
                ),
            )

            self.assertTrue(result.success, result.validation.errors)
            self.assertEqual(len(result.attempts), 2)
            self.assertEqual(provider_start_checks, [0, 1])
            self.assertEqual(
                executor.commands[1].argv[:4],
                ("codex", "exec", "resume", "thread-1"),
            )
            self.assertEqual(result.thread_id, "thread-1")
            self.assertEqual(result.usage.input_tokens, 20)
            self.assertEqual([candidate.value for candidate in flags], ["WACON{candidate_1}"])
            self.assertTrue(result.attempts[0].raw_jsonl_path.exists())
            self.assertTrue((root / "run" / "output-schema.json").exists())

    def test_wave_keeps_three_logical_roles_while_provider_serializes_calls(self) -> None:
        executor = SuccessfulSlowExecutor()
        limiter = FifoModelCallLimiter(1)
        runner = BatchRunner(
            process_executor=executor,
            limiter=limiter,
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocations = [
                BatchInvocation(
                    f"recon-{number}",
                    Role.RECON,
                    "inspect",
                    root,
                    root / f"run-{number}",
                )
                for number in range(3)
            ]
            wave = BatchWave.create("discovery", invocations)
            results = BatchWaveRunner(runner).run(wave)

        self.assertEqual(len(results), 3)
        self.assertEqual(executor.calls, 3)
        self.assertEqual(executor.max_active, 1)
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(
            {result.timing.session_created_at for result in results}, {wave.created_at}
        )
        self.assertGreater(max(result.timing.provider_wait_seconds for result in results), 0.02)
        self.assertEqual(limiter.snapshot().active, 0)
        self.assertEqual(limiter.snapshot().waiting, 0)

    def test_wave_rechecks_state_after_provider_wait_before_process_start(
        self,
    ) -> None:
        class BlockingFirstExecutor:
            def __init__(inner_self) -> None:
                inner_self.lock = threading.Lock()
                inner_self.first_started = threading.Event()
                inner_self.release = threading.Event()
                inner_self.calls = 0

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout, on_stdout_line
                with inner_self.lock:
                    inner_self.calls += 1
                    call_number = inner_self.calls
                if call_number != 1:
                    raise AssertionError(
                        "a provider call started after the terminal check"
                    )
                inner_self.first_started.set()
                if not inner_self.release.wait(timeout=2):
                    raise AssertionError("first provider call was not released")
                _output_path(command).write_text(
                    json.dumps(valid_payload(Role.RECON)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.0)

        executor = BlockingFirstExecutor()
        limiter = FifoModelCallLimiter(1)
        runner = BatchRunner(
            process_executor=executor,
            limiter=limiter,
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        terminal = threading.Event()
        callback_lock = threading.Lock()
        callback_states: list[bool] = []

        def check_before_start() -> None:
            blocked = terminal.is_set()
            with callback_lock:
                callback_states.append(blocked)
            if blocked:
                raise ModelCallLimitCancelled(
                    "challenge became terminal before provider start"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "terminal-during-provider-wait",
                [
                    BatchInvocation(
                        f"recon-{number}",
                        Role.RECON,
                        "inspect",
                        root,
                        root / f"run-{number}",
                    )
                    for number in range(3)
                ],
            )
            completed: list[tuple] = []
            failures: list[BaseException] = []

            def run_wave() -> None:
                try:
                    completed.append(
                        BatchWaveRunner(runner).run(
                            wave,
                            before_provider_start=check_before_start,
                        )
                    )
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=run_wave)
            thread.start()
            try:
                self.assertTrue(executor.first_started.wait(timeout=1))
                deadline = time.monotonic() + 1
                while (
                    limiter.snapshot().waiting < 2
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.005)
                self.assertEqual(limiter.snapshot().waiting, 2)
                terminal.set()
                executor.release.set()
                thread.join(timeout=2)
            finally:
                terminal.set()
                executor.release.set()
                thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(completed), 1)
        results = completed[0]
        self.assertEqual(executor.calls, 1)
        self.assertEqual(callback_states.count(False), 1)
        self.assertEqual(callback_states.count(True), 2)
        self.assertEqual(sum(result.success for result in results), 1)
        cancelled = [result for result in results if not result.success]
        self.assertEqual(len(cancelled), 2)
        self.assertTrue(
            all(
                any(
                    failure.kind == "model_call_cancelled"
                    for failure in result.failures
                )
                for result in cancelled
            )
        )
        self.assertEqual(limiter.snapshot().active, 0)
        self.assertEqual(limiter.snapshot().waiting, 0)

    def test_shared_file_limiter_keeps_three_logical_wave_roles(self) -> None:
        executor = SuccessfulSlowExecutor()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limiter = FileFifoModelCallLimiter(
                root / "model-calls.json",
                1,
                poll_interval=0.005,
            )
            runner = BatchRunner(
                process_executor=executor,
                limiter=limiter,
                limiter_wait_timeout=2,
                max_schema_retries=0,
            )
            invocations = [
                BatchInvocation(
                    f"recon-{number}",
                    Role.RECON,
                    "inspect",
                    root,
                    root / f"run-{number}",
                )
                for number in range(3)
            ]
            wave = BatchWave.create("shared-discovery", invocations)

            results = BatchWaveRunner(runner).run(wave)

            self.assertEqual(len(results), 3)
            self.assertEqual(
                [result.invocation.run_id for result in results],
                [invocation.run_id for invocation in invocations],
            )
            self.assertTrue(
                all(
                    len(result.attempts) == 1
                    and result.attempts[0].returncode == 0
                    for result in results
                )
            )
            self.assertEqual(executor.calls, 3)
            self.assertEqual(executor.max_active, 1)
            self.assertEqual(limiter.snapshot().active, 0)
            self.assertEqual(limiter.snapshot().waiting, 0)

    def test_runner_wait_uses_one_file_ticket_without_poll_rewrites(
        self,
    ) -> None:
        class NeverExecutor:
            def __init__(inner_self) -> None:
                inner_self.calls = 0

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del command, cwd, timeout, on_stdout_line
                inner_self.calls += 1
                raise AssertionError("cancelled waiter reached the provider")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "model-calls.json"
            limiter = FileFifoModelCallLimiter(
                state_path,
                1,
                poll_interval=0.005,
            )
            process_executor = NeverExecutor()
            runner = BatchRunner(
                process_executor=process_executor,
                limiter=limiter,
                limiter_wait_timeout=5,
                max_schema_retries=0,
            )
            invocation = BatchInvocation(
                "cancelled-waiter",
                Role.RECON,
                "wait",
                root,
                root / "cancelled-waiter",
            )
            cancel_event = threading.Event()
            results = []
            real_replace = os.replace
            state_rewrites: list[tuple[object, object]] = []

            def replace_and_count(source, destination):
                if Path(destination) == state_path:
                    state_rewrites.append((source, destination))
                return real_replace(source, destination)

            with mock.patch(
                "ctf_os.codex.limiter.os.replace",
                side_effect=replace_and_count,
            ):
                with limiter.slot(timeout=1) as model_call_slot:
                    model_call_slot.acquire()
                    waiter = threading.Thread(
                        target=lambda: results.append(
                            runner.run(
                                invocation,
                                _cancel_event=cancel_event,
                            )
                        )
                    )
                    waiter.start()
                    try:
                        queued = _wait_file_limiter_state(
                            state_path,
                            active=1,
                            waiting=1,
                        )
                        ticket = queued["queue"][0]["ticket"]
                        writes_after_enqueue = len(state_rewrites)

                        time.sleep(0.15)

                        stable = _wait_file_limiter_state(
                            state_path,
                            active=1,
                            waiting=1,
                        )
                        self.assertEqual(
                            stable["queue"][0]["ticket"],
                            ticket,
                        )
                        self.assertEqual(
                            len(state_rewrites),
                            writes_after_enqueue,
                        )

                        cancelled_at = time.monotonic()
                        cancel_event.set()
                        waiter.join(timeout=1)
                        self.assertFalse(waiter.is_alive())
                        self.assertLess(
                            time.monotonic() - cancelled_at,
                            0.5,
                        )
                        _wait_file_limiter_state(
                            state_path,
                            active=1,
                            waiting=0,
                        )
                        self.assertEqual(
                            len(state_rewrites),
                            writes_after_enqueue + 1,
                        )
                    finally:
                        cancel_event.set()
                        waiter.join(timeout=2)

            self.assertEqual(process_executor.calls, 0)
            self.assertEqual(len(results), 1)
            self.assertFalse(results[0].success)
            self.assertEqual(limiter.snapshot().active, 0)
            self.assertEqual(limiter.snapshot().waiting, 0)

    def test_limiter_timeout_is_a_failed_result_not_an_exception(self) -> None:
        limiter = FifoModelCallLimiter(1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocation = BatchInvocation(
                "recon-timeout", Role.RECON, "inspect", root, root / "run"
            )
            with limiter.slot() as model_call_slot:
                model_call_slot.acquire()
                result = BatchRunner(
                    process_executor=SuccessfulSlowExecutor(),
                    limiter=limiter,
                    limiter_wait_timeout=0.02,
                    max_schema_retries=0,
                ).run(invocation)
        self.assertFalse(result.success)
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(result.attempts[0].returncode, 124)
        self.assertEqual(result.failures[0].kind, "model_call_wait_timeout")

    def test_wave_preserves_completed_results_when_one_role_launch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocations = [
                BatchInvocation(
                    f"role-{number}",
                    Role.RECON,
                    "inspect",
                    root,
                    root / f"run-{number}",
                )
                for number in (1, 2, 3)
            ]
            wave = BatchWave.create("partial", invocations)
            results = BatchWaveRunner(
                BatchRunner(
                    process_executor=SelectiveFailureExecutor(),
                    max_schema_retries=0,
                )
            ).run(wave)

        self.assertEqual(
            [result.invocation.run_id for result in results],
            ["role-1", "role-2", "role-3"],
        )
        self.assertEqual([result.success for result in results], [True, False, True])
        self.assertEqual(results[1].failures[0].kind, "process_launch")
        self.assertEqual(len(results[0].attempts), 1)
        self.assertEqual(len(results[2].attempts), 1)

    def test_wave_waits_for_retained_process_cleanup_before_return(
        self,
    ) -> None:
        cleanup_denied = threading.Event()
        allow_cleanup = threading.Event()
        cleanup_attempts = 0
        real_killpg = runner_module.os.killpg

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "run"
            output.mkdir()
            pid_path = root / "child.pid"
            build_calls = 0

            class SleepingBuilder:
                def build(
                    self,
                    _invocation,
                    _schema_path,
                    _output_path,
                    **_kwargs,
                ):
                    nonlocal build_calls
                    build_calls += 1
                    script = (
                        "import os,pathlib,signal,sys,time;"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                        "pathlib.Path(sys.argv[1]).write_text("
                        "str(os.getpid()));"
                        "print('{}',flush=True);"
                        "time.sleep(30)"
                    )
                    return BuiltCommand(
                        (
                            sys.executable,
                            "-c",
                            script,
                            str(pid_path),
                        ),
                        "",
                    )

            def deny_until_released(
                process_group: int,
                sent_signal: int,
            ) -> None:
                nonlocal cleanup_attempts
                if not allow_cleanup.is_set():
                    cleanup_attempts += 1
                    cleanup_denied.set()
                    raise PermissionError(
                        "synthetic persistent killpg denial"
                    )
                real_killpg(process_group, sent_signal)

            def release_cleanup() -> None:
                if cleanup_denied.wait(timeout=2):
                    time.sleep(0.15)
                    allow_cleanup.set()

            executor = SubprocessExecutor(
                terminate_grace_seconds=0.05,
                drain_grace_seconds=0.05,
            )
            runner = BatchRunner(
                command_builder=SleepingBuilder(),
                process_executor=executor,
                max_schema_retries=1,
            )
            invocation = BatchInvocation(
                "retained-cleanup",
                Role.RECON,
                "inspect",
                root,
                output,
                timeout_seconds=0.1,
                deadline_monotonic_seconds=time.monotonic() + 0.2,
            )
            releaser = threading.Thread(target=release_cleanup)
            releaser.start()
            child_pid: int | None = None
            started = time.monotonic()
            try:
                with mock.patch.object(
                    runner_module.os,
                    "killpg",
                    side_effect=deny_until_released,
                ):
                    results = BatchWaveRunner(runner).run(
                        BatchWave.create(
                            "retained-cleanup-wave",
                            (invocation,),
                        )
                    )
                elapsed = time.monotonic() - started
                child_pid = int(pid_path.read_text(encoding="utf-8"))
            finally:
                allow_cleanup.set()
                releaser.join(timeout=1)
                executor.cancel_active()
                if (
                    child_pid is not None
                    and Path(f"/proc/{child_pid}").exists()
                ):
                    try:
                        real_killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child_pid, 0)
                    except ChildProcessError:
                        pass

        self.assertFalse(releaser.is_alive())
        self.assertTrue(cleanup_denied.is_set())
        self.assertGreaterEqual(cleanup_attempts, 2)
        self.assertGreaterEqual(elapsed, 0.14)
        self.assertEqual(build_calls, 1)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].success)
        self.assertEqual(len(results[0].attempts), 1)
        self.assertTrue(
            any(
                failure.kind == "process_launch"
                and "persistent killpg denial" in failure.message
                for failure in results[0].failures
            )
        )
        assert child_pid is not None
        self.assertFalse(Path(f"/proc/{child_pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_wave_later_flag_notification_failure_promptly_cancels_siblings(
        self,
    ) -> None:
        all_started = threading.Barrier(3)
        cancel_active_called = threading.Event()
        sibling_cancelled = {
            "blocked-first": threading.Event(),
            "blocked-third": threading.Event(),
        }

        class LaterNotificationFailureRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                cancel_event = kwargs["_cancel_event"]
                all_started.wait(timeout=2)
                if invocation.run_id == "fatal-second":
                    raise FlagNotificationError(
                        "later invocation could not notify its flag"
                    )
                if not cancel_event.wait(timeout=2):
                    raise AssertionError(
                        "a later fatal notification did not cancel siblings"
                    )
                sibling_cancelled[invocation.run_id].set()
                return self.failed_result(
                    invocation,
                    ModelCallLimitCancelled("wave was cancelled"),
                    session_created_at=kwargs["session_created_at"],
                )

            def cancel_active(self, *, cancel_event=None) -> None:
                if cancel_event is None:
                    raise AssertionError("wave cancellation must be scoped")
                cancel_active_called.set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "later-fatal-notification",
                [
                    BatchInvocation(
                        "blocked-first",
                        Role.RECON,
                        "wait",
                        root,
                        root / "run-first",
                    ),
                    BatchInvocation(
                        "fatal-second",
                        Role.SPECIALIST,
                        "fail",
                        root,
                        root / "run-second",
                    ),
                    BatchInvocation(
                        "blocked-third",
                        Role.EXTRACTOR,
                        "wait",
                        root,
                        root / "run-third",
                    ),
                ],
            )
            started = time.monotonic()
            with self.assertRaisesRegex(
                FlagNotificationError,
                "later invocation",
            ):
                BatchWaveRunner(
                    LaterNotificationFailureRunner(max_schema_retries=0)
                ).run(wave)
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1.0)
        self.assertTrue(cancel_active_called.wait(1))
        self.assertTrue(sibling_cancelled["blocked-first"].wait(1))
        self.assertTrue(sibling_cancelled["blocked-third"].wait(1))

    def test_wave_interrupt_joins_active_worker_before_return(
        self,
    ) -> None:
        worker_active = threading.Event()
        release_worker = threading.Event()
        worker_finished = threading.Event()

        class DelayedPostprocessRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                cancel_event = kwargs["_cancel_event"]
                if invocation.run_id == "delayed":
                    worker_active.set()
                    if not release_worker.wait(timeout=2):
                        raise AssertionError("delayed worker was not released")
                    worker_finished.set()
                    return self.failed_result(
                        invocation,
                        RuntimeError("delayed worker completed"),
                        session_created_at=kwargs["session_created_at"],
                    )
                if invocation.run_id == "interrupt":
                    if not worker_active.wait(timeout=2):
                        raise AssertionError("delayed worker did not start")
                    raise KeyboardInterrupt(
                        "synthetic wave owner interruption"
                    )
                if not cancel_event.wait(timeout=2):
                    raise AssertionError("wave cancellation was not published")
                return self.failed_result(
                    invocation,
                    ModelCallLimitCancelled("wave was cancelled"),
                    session_created_at=kwargs["session_created_at"],
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "join-before-return",
                [
                    BatchInvocation(
                        "delayed",
                        Role.RECON,
                        "delay",
                        root,
                        root / "run-delayed",
                    ),
                    BatchInvocation(
                        "interrupt",
                        Role.SPECIALIST,
                        "interrupt",
                        root,
                        root / "run-interrupt",
                    ),
                    BatchInvocation(
                        "waiting",
                        Role.EXTRACTOR,
                        "wait",
                        root,
                        root / "run-waiting",
                    ),
                ],
            )

            def release_after_observation() -> None:
                if worker_active.wait(timeout=2):
                    time.sleep(0.1)
                    release_worker.set()

            releaser = threading.Thread(target=release_after_observation)
            releaser.start()
            started = time.monotonic()
            with self.assertRaises(KeyboardInterrupt):
                BatchWaveRunner(
                    DelayedPostprocessRunner(max_schema_retries=0)
                ).run(wave)
            elapsed = time.monotonic() - started
            releaser.join(timeout=1)

        self.assertTrue(worker_finished.is_set())
        self.assertFalse(releaser.is_alive())
        self.assertGreaterEqual(elapsed, 0.09)
        self.assertLess(elapsed, 1.0)

    def test_wave_start_registry_interrupt_waits_for_unregistered_worker(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic worker registry interrupt"),
            SystemExit("synthetic worker registry exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                entered = threading.Event()
                release = threading.Event()
                finished = threading.Event()
                started_threads: list[threading.Thread] = []

                class BlockingRunner(BatchRunner):
                    def run(self, invocation, **kwargs):
                        entered.set()
                        if not release.wait(timeout=2):
                            raise AssertionError(
                                "unregistered worker was not released"
                            )
                        finished.set()
                        return self.failed_result(
                            invocation,
                            RuntimeError("synthetic worker completion"),
                            session_created_at=kwargs[
                                "session_created_at"
                            ],
                        )

                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    wave = BatchWave.create(
                        "start-registry",
                        (
                            BatchInvocation(
                                "unregistered",
                                Role.RECON,
                                "wait",
                                root,
                                root / "run-unregistered",
                            ),
                        ),
                    )
                    real_start = threading.Thread.start

                    def start_then_interrupt(
                        thread: threading.Thread,
                    ) -> None:
                        real_start(thread)
                        if thread.name.startswith(
                            "ctfos-start-registry"
                        ):
                            started_threads.append(thread)
                            if not entered.wait(timeout=1):
                                raise AssertionError(
                                    "worker did not enter dispatch"
                                )
                            raise interruption

                    def release_after_entry() -> None:
                        if entered.wait(timeout=1):
                            time.sleep(0.1)
                            release.set()

                    releaser = threading.Thread(
                        target=release_after_entry
                    )
                    releaser.start()
                    started = time.monotonic()
                    try:
                        with (
                            mock.patch.object(
                                threading.Thread,
                                "start",
                                new=start_then_interrupt,
                            ),
                            self.assertRaises(
                                type(interruption)
                            ) as raised,
                        ):
                            BatchWaveRunner(
                                BlockingRunner(max_schema_retries=0)
                            ).run(wave)
                    finally:
                        release.set()
                        releaser.join(timeout=1)
                    elapsed = time.monotonic() - started

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(started_threads), 1)
                started_threads[0].join(timeout=1)
                self.assertFalse(started_threads[0].is_alive())
                self.assertTrue(finished.is_set())
                self.assertGreaterEqual(elapsed, 0.09)
                self.assertLess(elapsed, 1.0)

    def test_wave_cancel_active_interrupt_does_not_skip_worker_drain(
        self,
    ) -> None:
        owner_error = KeyboardInterrupt(
            "synthetic wave owner interruption"
        )
        cleanup_error = SystemExit(
            "synthetic cancel_active interruption"
        )
        active = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        class InterruptedCleanupRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                if invocation.run_id == "active":
                    active.set()
                    if not release.wait(timeout=2):
                        raise AssertionError(
                            "active callback was not released"
                        )
                    finished.set()
                    return self.failed_result(
                        invocation,
                        RuntimeError("synthetic callback completion"),
                        session_created_at=kwargs["session_created_at"],
                    )
                if not active.wait(timeout=1):
                    raise AssertionError(
                        "sibling callback did not become active"
                    )
                raise owner_error

            def cancel_active(self, *, cancel_event=None) -> None:
                if cancel_event is None:
                    raise AssertionError(
                        "wave cancellation must remain scoped"
                    )
                raise cleanup_error

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "cancel-active-interrupt",
                (
                    BatchInvocation(
                        "active",
                        Role.RECON,
                        "wait",
                        root,
                        root / "run-active",
                    ),
                    BatchInvocation(
                        "interrupt",
                        Role.SPECIALIST,
                        "interrupt",
                        root,
                        root / "run-interrupt",
                    ),
                ),
            )

            def release_after_entry() -> None:
                if active.wait(timeout=1):
                    time.sleep(0.1)
                    release.set()

            releaser = threading.Thread(target=release_after_entry)
            releaser.start()
            started = time.monotonic()
            try:
                with self.assertRaises(KeyboardInterrupt) as raised:
                    BatchWaveRunner(
                        InterruptedCleanupRunner(max_schema_retries=0)
                    ).run(wave)
            finally:
                release.set()
                releaser.join(timeout=1)
            elapsed = time.monotonic() - started

        self.assertIs(raised.exception, owner_error)
        self.assertTrue(finished.is_set())
        self.assertGreaterEqual(elapsed, 0.09)
        self.assertLess(elapsed, 1.0)
        self.assertTrue(
            any(
                "active-process cancellation failed" in note
                and "synthetic cancel_active interruption" in note
                for note in owner_error.__notes__
            )
        )

    def test_wave_cleanup_control_supersedes_ordinary_wave_failure(
        self,
    ) -> None:
        wave_failure = FlagNotificationError(
            "synthetic ordinary wave failure"
        )
        cleanup_interruption = KeyboardInterrupt(
            "synthetic first wave cleanup interrupt"
        )

        class CleanupInterruptRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                del invocation, kwargs
                raise wave_failure

            def cancel_active(self, *, cancel_event=None) -> None:
                if cancel_event is None:
                    raise AssertionError(
                        "wave cancellation must remain scoped"
                    )
                raise cleanup_interruption

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "ordinary-then-control",
                (
                    BatchInvocation(
                        "fatal",
                        Role.RECON,
                        "fail",
                        root,
                        root / "run-fatal",
                    ),
                ),
            )
            with self.assertRaises(KeyboardInterrupt) as raised:
                BatchWaveRunner(
                    CleanupInterruptRunner(max_schema_retries=0)
                ).run(wave)

        self.assertIs(raised.exception, cleanup_interruption)
        self.assertTrue(
            any(
                "synthetic ordinary wave failure" in note
                for note in cleanup_interruption.__notes__
            )
        )

    def test_wave_close_interrupt_blocks_late_unregistered_dispatch(
        self,
    ) -> None:
        owner_error = KeyboardInterrupt(
            "synthetic worker start interruption"
        )
        cleanup_error = SystemExit(
            "synthetic gate close interruption"
        )
        before_admission = threading.Event()
        release_admission = threading.Event()
        callback_entered = threading.Event()
        started_threads: list[threading.Thread] = []
        close_calls = 0
        real_start = threading.Thread.start
        real_dispatch = runner_module._WaveDispatchGate.run
        real_close = runner_module._WaveDispatchGate.close

        class RecordingRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                del invocation, kwargs
                callback_entered.set()
                raise AssertionError(
                    "closed late dispatch entered the callback"
                )

        def delay_before_admission(gate, callback):
            before_admission.set()
            if not release_admission.wait(timeout=2):
                raise AssertionError("late dispatch was not released")
            return real_dispatch(gate, callback)

        def start_then_interrupt(thread: threading.Thread) -> None:
            real_start(thread)
            if thread.name.startswith("ctfos-close-interrupt"):
                started_threads.append(thread)
                if not before_admission.wait(timeout=1):
                    raise AssertionError(
                        "worker did not reach dispatch admission"
                    )
                raise owner_error

        def close_then_interrupt(gate) -> None:
            nonlocal close_calls
            close_calls += 1
            if close_calls == 1:
                raise cleanup_error
            real_close(gate)
            release_admission.set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "close-interrupt",
                (
                    BatchInvocation(
                        "late",
                        Role.RECON,
                        "wait",
                        root,
                        root / "run-late",
                    ),
                ),
            )
            try:
                with (
                    mock.patch.object(
                        threading.Thread,
                        "start",
                        new=start_then_interrupt,
                    ),
                    mock.patch.object(
                        runner_module._WaveDispatchGate,
                        "run",
                        new=delay_before_admission,
                    ),
                    mock.patch.object(
                        runner_module._WaveDispatchGate,
                        "close",
                        new=close_then_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    BatchWaveRunner(
                        RecordingRunner(max_schema_retries=0)
                    ).run(wave)
            finally:
                release_admission.set()

        self.assertIs(raised.exception, owner_error)
        self.assertEqual(close_calls, 2)
        self.assertEqual(len(started_threads), 1)
        started_threads[0].join(timeout=1)
        self.assertFalse(started_threads[0].is_alive())
        self.assertFalse(callback_entered.is_set())
        self.assertTrue(
            any(
                "dispatch closure cleanup" in note
                and "synthetic gate close interruption" in note
                for note in owner_error.__notes__
            )
        )

    def test_wave_persistent_gate_cleanup_uses_bounded_backoff_and_notes(
        self,
    ) -> None:
        wave_failure = FlagNotificationError(
            "synthetic wave failure before gate cleanup"
        )
        attempts = 0
        real_close = runner_module._WaveDispatchGate.close
        recover_at = 0.0

        class FailingRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                del invocation, kwargs
                raise wave_failure

        def fail_then_close(gate) -> None:
            nonlocal attempts
            attempts += 1
            if time.monotonic() < recover_at:
                raise RuntimeError("synthetic persistent gate close failure")
            real_close(gate)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "bounded-gate-cleanup",
                (
                    BatchInvocation(
                        "fatal",
                        Role.RECON,
                        "fail",
                        root,
                        root / "run-fatal",
                    ),
                ),
            )
            started = time.monotonic()
            recover_at = started + 0.05
            with (
                mock.patch.object(
                    runner_module._WaveDispatchGate,
                    "close",
                    new=fail_then_close,
                ),
                self.assertRaises(FlagNotificationError) as raised,
            ):
                BatchWaveRunner(
                    FailingRunner(max_schema_retries=0)
                ).run(wave)
            elapsed = time.monotonic() - started

        self.assertIs(raised.exception, wave_failure)
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertGreaterEqual(attempts, 2)
        self.assertLess(attempts, 20)
        self.assertLessEqual(len(wave_failure.__notes__), 3)
        self.assertTrue(
            any(
                "recovered after" in note
                for note in wave_failure.__notes__
            )
        )

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc").exists(),
        "requires Linux /proc",
    )
    def test_wave_keyboard_interrupt_cancels_and_reaps_active_processes(
        self,
    ) -> None:
        active = threading.Event()
        child_pids: list[int] = []

        class SleepingCommandBuilder:
            def build(
                self,
                invocation,
                schema_path,
                output_path,
                **kwargs,
            ):
                del invocation, schema_path, output_path, kwargs
                script = (
                    "import json,os,signal,time;"
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                    "print(json.dumps({"
                    "'type':'thread.started','thread_id':'sleeping',"
                    "'pid':os.getpid()"
                    "}),flush=True);"
                    "time.sleep(30)"
                )
                return BuiltCommand((sys.executable, "-c", script), "")

        class InterruptingRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                if invocation.run_id == "interrupt":
                    if not active.wait(2):
                        raise AssertionError(
                            "the sibling process did not become active"
                        )
                    raise KeyboardInterrupt
                return super().run(invocation, **kwargs)

        def observe(event) -> None:
            pid = event.payload.get("pid")
            if isinstance(pid, int):
                child_pids.append(pid)
                active.set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invocations = [
                BatchInvocation(
                    "interrupt",
                    Role.RECON,
                    "interrupt",
                    root,
                    root / "run-interrupt",
                    timeout_seconds=30,
                ),
                BatchInvocation(
                    "active",
                    Role.RECON,
                    "sleep",
                    root,
                    root / "run-active",
                    timeout_seconds=30,
                ),
                BatchInvocation(
                    "waiting",
                    Role.RECON,
                    "wait",
                    root,
                    root / "run-waiting",
                    timeout_seconds=30,
                ),
            ]
            runner = InterruptingRunner(
                command_builder=SleepingCommandBuilder(),
                process_executor=SubprocessExecutor(
                    terminate_grace_seconds=0.1,
                    drain_grace_seconds=0.1,
                ),
                limiter=FifoModelCallLimiter(1),
                max_schema_retries=0,
            )
            started = time.monotonic()
            with self.assertRaises(KeyboardInterrupt):
                BatchWaveRunner(runner).run(
                    BatchWave.create("interrupt-wave", invocations),
                    on_event=observe,
                )
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 1.5)
        self.assertEqual(len(child_pids), 1)
        for child_pid in child_pids:
            deadline = time.monotonic() + 1
            while (
                Path(f"/proc/{child_pid}").exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_wave_interrupt_cancels_provider_waiters_without_deadline_wait(
        self,
    ) -> None:
        limiter = FifoModelCallLimiter(1)
        waiter_results = []
        waiter_finished = threading.Event()

        class NeverExecutor:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, command, *, cwd, timeout, on_stdout_line):
                del command, cwd, timeout, on_stdout_line
                self.calls += 1
                raise AssertionError("a cancelled provider waiter ran")

        class WaitingInterruptRunner(BatchRunner):
            def run(self, invocation, **kwargs):
                if invocation.run_id == "interrupt":
                    deadline = time.monotonic() + 2
                    while (
                        limiter.snapshot().waiting < 1
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.005)
                    if limiter.snapshot().waiting < 1:
                        raise AssertionError(
                            "the sibling did not enter the provider queue"
                        )
                    raise KeyboardInterrupt
                result = super().run(invocation, **kwargs)
                waiter_results.append(result)
                waiter_finished.set()
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wave = BatchWave.create(
                "waiter-interrupt",
                [
                    BatchInvocation(
                        "interrupt",
                        Role.RECON,
                        "interrupt",
                        root,
                        root / "run-interrupt",
                    ),
                    BatchInvocation(
                        "waiting",
                        Role.RECON,
                        "wait",
                        root,
                        root / "run-waiting",
                    ),
                ],
            )
            process_executor = NeverExecutor()
            runner = WaitingInterruptRunner(
                process_executor=process_executor,
                limiter=limiter,
                limiter_wait_timeout=30,
                max_schema_retries=0,
            )
            with limiter.slot() as model_call_slot:
                model_call_slot.acquire()
                with self.assertRaises(KeyboardInterrupt):
                    BatchWaveRunner(runner).run(wave)
                # BatchWaveRunner drains admitted workers before propagating the
                # interrupt. The external holder still owns all capacity here,
                # so the sibling can only have finished by observing
                # cancellation (not by acquiring a slot).
                self.assertTrue(waiter_finished.is_set())
                self.assertEqual(
                    limiter.snapshot(),
                    LimiterSnapshot(1, 1, 0),
                )

        self.assertEqual(process_executor.calls, 0)
        self.assertEqual(len(waiter_results), 1)
        waiter_result = waiter_results[0]
        self.assertFalse(waiter_result.success)
        self.assertEqual(len(waiter_result.attempts), 1)
        self.assertEqual(waiter_result.attempts[0].returncode, 130)
        self.assertFalse(waiter_result.attempts[0].timed_out)
        self.assertIn(
            "model_call_cancelled",
            {failure.kind for failure in waiter_result.failures},
        )
        self.assertNotIn(
            "model_call_wait_timeout",
            {failure.kind for failure in waiter_result.failures},
        )
        self.assertEqual(limiter.snapshot(), LimiterSnapshot(1, 0, 0))


@unittest.skipUnless(os.name == "posix" and Path("/proc").exists(), "requires Linux /proc")
class SubprocessExecutorTests(unittest.TestCase):
    def test_caller_store_interrupt_reaps_pending_process_handoff(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        interruption = KeyboardInterrupt(
            "synthetic direct caller store interrupt"
        )
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_killpg = os.killpg
        real_helper = runner_module._popen_with_constructor_cleanup

        def interrupt_after_helper_return(*args, **kwargs):
            process = real_helper(*args, **kwargs)
            pending = kwargs["pending_handoff"]
            self.assertIs(pending[0], process)
            spawned_pids.append(process.pid)
            raise interruption

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        script = "import time;time.sleep(30)"
        with (
            mock.patch.object(
                runner_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            mock.patch.object(
                runner_module,
                "_popen_with_constructor_cleanup",
                side_effect=interrupt_after_helper_return,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        deadline = time.monotonic() + 1
        while (
            Path(f"/proc/{child_pid}").exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{child_pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_constructor_interrupt_reaps_partial_process_group(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        interruption = KeyboardInterrupt(
            "synthetic constructor interrupt"
        )
        spawned_pids: list[int] = []
        signals: list[tuple[int, int]] = []
        real_execute_child = subprocess.Popen._execute_child
        real_killpg = os.killpg

        def interrupt_after_execute(process, *args, **kwargs):
            real_execute_child(process, *args, **kwargs)
            spawned_pids.append(process.pid)
            raise interruption

        def record_killpg(process_group: int, sent_signal: int) -> None:
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                signals.append((process_group, sent_signal))
            real_killpg(process_group, sent_signal)

        script = "import time;time.sleep(30)"
        with (
            mock.patch.object(
                subprocess.Popen,
                "_execute_child",
                new=interrupt_after_execute,
            ),
            mock.patch.object(
                runner_module.os,
                "killpg",
                side_effect=record_killpg,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        child_pid = spawned_pids[0]
        self.assertEqual(
            signals,
            [
                (child_pid, signal.SIGTERM),
                (child_pid, signal.SIGKILL),
            ],
        )
        deadline = time.monotonic() + 1
        while (
            Path(f"/proc/{child_pid}").exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{child_pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_registration_interrupt_reaps_untracked_process_group(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        interruption = KeyboardInterrupt(
            "synthetic registration interrupt"
        )
        spawned_pids: list[int] = []
        real_popen = runner_module.subprocess.Popen

        class InterruptingLock:
            def __init__(self) -> None:
                self._lock = threading.Lock()
                self._interrupt = True

            def __enter__(self):
                if self._interrupt:
                    self._interrupt = False
                    raise interruption
                self._lock.acquire()
                return self

            def __exit__(self, *_args) -> None:
                self._lock.release()

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            return process

        executor._active_lock = InterruptingLock()
        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        with (
            mock.patch.object(
                runner_module.subprocess,
                "Popen",
                side_effect=recording_popen,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(spawned_pids), 1)
        process_path = Path(f"/proc/{spawned_pids[0]}")
        deadline = time.monotonic() + 1
        while process_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(process_path.exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_pump_start_return_interrupt_preserves_started_owner(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.05,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic pump start return interrupt"
        )
        real_start = runner_module.threading.Thread.start
        real_terminate = executor._terminate_processes
        started_thread: threading.Thread | None = None
        observed_started_owner = False
        spawned_pids: list[int] = []
        real_popen = runner_module.subprocess.Popen

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            return process

        def start_then_interrupt(thread: threading.Thread) -> None:
            nonlocal started_thread
            real_start(thread)
            if started_thread is None:
                started_thread = thread
                raise interruption

        def inspect_then_terminate(
            processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            nonlocal observed_started_owner
            with executor._active_lock:
                for process in processes:
                    owned = executor._pump_controls.get(process.pid)
                    if owned is None or owned[0] is not process:
                        continue
                    stdout_owner = owned[1].threads.get("stdout")
                    observed_started_owner = (
                        stdout_owner is started_thread
                        and stdout_owner is not None
                        and stdout_owner.ident is not None
                    )
            real_terminate(processes)

        with (
            mock.patch.object(
                runner_module.subprocess,
                "Popen",
                side_effect=recording_popen,
            ),
            mock.patch.object(
                runner_module.threading.Thread,
                "start",
                new=start_then_interrupt,
            ),
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=inspect_then_terminate,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand(
                    (
                        sys.executable,
                        "-c",
                        "import time;time.sleep(30)",
                    ),
                    "",
                ),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(observed_started_owner)
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(Path(f"/proc/{spawned_pids[0]}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_pump_delayed_bootstrap_blocks_owner_unwind_until_close(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic delayed pump bootstrap interrupt"
        )
        bootstrap_entered = threading.Event()
        cleanup_attempted = threading.Event()
        release_bootstrap = threading.Event()
        real_thread = runner_module.threading.Thread
        real_popen = runner_module.subprocess.Popen
        real_terminate = executor._terminate_processes
        delayed_threads: list[threading.Thread] = []
        spawned_processes: list[subprocess.Popen[bytes]] = []

        class DelayedStartedEvent:
            def __init__(self, event: threading.Event) -> None:
                self._event = event

            def is_set(self) -> bool:
                return self._event.is_set()

            def set(self) -> None:
                self._event.set()

            def wait(self, timeout: float | None = None) -> bool:
                del timeout
                bootstrap_entered.wait()
                raise interruption

        def delayed_thread_factory(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            target = kwargs.get("target")
            if getattr(target, "__name__", "") not in {
                "pump",
                "pump_stdin",
            }:
                return thread
            original_inner = thread._bootstrap_inner
            original_started = thread._started

            def delayed_inner() -> None:
                bootstrap_entered.set()
                release_bootstrap.wait()
                original_inner()

            thread._bootstrap_inner = delayed_inner
            thread._started = DelayedStartedEvent(original_started)
            delayed_threads.append(thread)
            return thread

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_processes.append(process)
            return process

        def observe_cleanup(
            processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            cleanup_attempted.set()
            real_terminate(processes)

        def release_after_cleanup_attempt() -> None:
            bootstrap_entered.wait(timeout=2)
            cleanup_attempted.wait(timeout=2)
            time.sleep(0.1)
            release_bootstrap.set()

        releaser = real_thread(target=release_after_cleanup_attempt)
        releaser.start()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    runner_module.threading,
                    "Thread",
                    side_effect=delayed_thread_factory,
                ),
                mock.patch.object(
                    runner_module.subprocess,
                    "Popen",
                    side_effect=recording_popen,
                ),
                mock.patch.object(
                    executor,
                    "_terminate_processes",
                    side_effect=observe_cleanup,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                executor.run(
                    BuiltCommand(
                        (
                            sys.executable,
                            "-c",
                            "import time;time.sleep(30)",
                        ),
                        "",
                    ),
                    cwd=Path.cwd(),
                    timeout=30,
                    on_stdout_line=lambda _line: None,
                )
        finally:
            release_bootstrap.set()
            releaser.join(timeout=2)

        elapsed = time.monotonic() - started
        self.assertIs(raised.exception, interruption)
        self.assertTrue(bootstrap_entered.is_set())
        self.assertTrue(cleanup_attempted.is_set())
        self.assertGreaterEqual(elapsed, 0.09)
        self.assertFalse(releaser.is_alive())
        self.assertTrue(delayed_threads)
        self.assertTrue(all(not thread.is_alive() for thread in delayed_threads))
        self.assertEqual(len(spawned_processes), 1)
        self.assertTrue(spawned_processes[0].stdout.closed)
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_pump_pre_native_start_failure_retires_unstarted_owner(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        failure = RuntimeError("synthetic pre-native pump start failure")
        real_popen = runner_module.subprocess.Popen
        spawned_processes: list[subprocess.Popen[bytes]] = []

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_processes.append(process)
            return process

        def fail_before_native_start(_thread: threading.Thread) -> None:
            raise failure

        with (
            mock.patch.object(
                runner_module.subprocess,
                "Popen",
                side_effect=recording_popen,
            ),
            mock.patch.object(
                runner_module.threading.Thread,
                "start",
                new=fail_before_native_start,
            ),
            self.assertRaises(RuntimeError) as raised,
        ):
            executor.run(
                BuiltCommand(
                    (
                        sys.executable,
                        "-c",
                        "import time;time.sleep(30)",
                    ),
                    "",
                ),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, failure)
        self.assertEqual(len(spawned_processes), 1)
        process = spawned_processes[0]
        self.assertTrue(process.stdout.closed)
        self.assertFalse(Path(f"/proc/{process.pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_stdin_close_failure_blocks_owner_unwind_until_recovered(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        persistent = RuntimeError("synthetic persistent stdin close failure")
        failure_published = threading.Event()
        recovery_complete = threading.Event()
        owner_retained = False
        recovery_errors: list[BaseException] = []
        real_close = runner_module._close_stream_bounded
        injected = False

        def fail_first_stdin_close(stream, *, label):
            nonlocal injected
            if label == "stdin" and not injected:
                injected = True
                failure_published.set()
                return persistent, False
            return real_close(stream, label=label)

        def recover_exact_stdin_owner() -> None:
            nonlocal owner_retained
            if not failure_published.wait(timeout=2):
                recovery_errors.append(
                    RuntimeError("stdin close failure was not published")
                )
                recovery_complete.set()
                return
            time.sleep(0.1)
            try:
                with executor._active_lock:
                    owner_retained = bool(executor._active_processes)
                    process, _event, _token = next(
                        iter(executor._active_processes.values())
                    )
                    control = executor._pump_controls[process.pid][1]
                close_result = real_close(process.stdin, label="stdin")
                control.record_close("stdin", close_result)
            except BaseException as error:
                recovery_errors.append(error)
            finally:
                recovery_complete.set()

        releaser = threading.Thread(target=recover_exact_stdin_owner)
        releaser.start()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    runner_module,
                    "_close_stream_bounded",
                    side_effect=fail_first_stdin_close,
                ),
                self.assertRaises(RuntimeError) as raised,
            ):
                executor.run(
                    BuiltCommand((sys.executable, "-c", "pass"), ""),
                    cwd=Path.cwd(),
                    timeout=1,
                    on_stdout_line=lambda _line: None,
                )
        finally:
            recovery_complete.wait(timeout=2)
            releaser.join(timeout=2)

        elapsed = time.monotonic() - started
        self.assertIn(
            "stdin pump cleanup did not complete",
            str(raised.exception),
        )
        self.assertTrue(owner_retained)
        self.assertFalse(recovery_errors)
        self.assertFalse(releaser.is_alive())
        self.assertGreaterEqual(elapsed, 0.09)
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_confirmed_stdin_close_propagates_control_once_then_cleans(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic post-close stdin interrupt"
        )
        real_close = runner_module._close_stream_bounded
        injected = False

        def close_then_interrupt(stream, *, label):
            nonlocal injected
            result = real_close(stream, label=label)
            if label == "stdin" and not injected:
                injected = True
                self.assertTrue(result[1])
                return interruption, True
            return result

        with (
            mock.patch.object(
                runner_module,
                "_close_stream_bounded",
                side_effect=close_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", "pass"), ""),
                cwd=Path.cwd(),
                timeout=1,
                on_stdout_line=lambda _line: None,
            )

        self.assertTrue(injected)
        self.assertIs(raised.exception, interruption)
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_unconfirmed_stdin_close_control_is_not_replayed_as_second(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic unconfirmed stdin close interrupt"
        )
        failure_published = threading.Event()
        recovery_complete = threading.Event()
        owner_retained = False
        recovery_errors: list[BaseException] = []
        real_close = runner_module._close_stream_bounded
        injected = False

        def interrupt_first_stdin_close(stream, *, label):
            nonlocal injected
            if label == "stdin" and not injected:
                injected = True
                failure_published.set()
                return interruption, False
            return real_close(stream, label=label)

        def recover_exact_stdin_owner() -> None:
            nonlocal owner_retained
            if not failure_published.wait(timeout=2):
                recovery_errors.append(
                    RuntimeError("stdin close interrupt was not published")
                )
                recovery_complete.set()
                return
            time.sleep(0.1)
            try:
                with executor._active_lock:
                    owner_retained = bool(executor._active_processes)
                    process, _event, _token = next(
                        iter(executor._active_processes.values())
                    )
                    control = executor._pump_controls[process.pid][1]
                close_result = real_close(process.stdin, label="stdin")
                control.record_close("stdin", close_result)
            except BaseException as error:
                recovery_errors.append(error)
            finally:
                recovery_complete.set()

        releaser = threading.Thread(target=recover_exact_stdin_owner)
        releaser.start()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    runner_module,
                    "_close_stream_bounded",
                    side_effect=interrupt_first_stdin_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                executor.run(
                    BuiltCommand((sys.executable, "-c", "pass"), ""),
                    cwd=Path.cwd(),
                    timeout=1,
                    on_stdout_line=lambda _line: None,
                )
        finally:
            recovery_complete.wait(timeout=2)
            releaser.join(timeout=2)

        elapsed = time.monotonic() - started
        self.assertIs(raised.exception, interruption)
        self.assertTrue(owner_retained)
        self.assertFalse(recovery_errors)
        self.assertFalse(releaser.is_alive())
        self.assertGreaterEqual(elapsed, 0.09)
        self.assertFalse(
            any(
                "second" in note and "control" in note
                for note in interruption.__notes__
            )
        )
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_registration_interrupt_waits_for_exact_cleanup_before_propagating(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.05,
            drain_grace_seconds=0.05,
        )
        interruption = KeyboardInterrupt(
            "synthetic registration lock interrupt"
        )
        spawned_processes: list[subprocess.Popen[bytes]] = []
        real_popen = runner_module.subprocess.Popen
        real_killpg = runner_module.os.killpg
        cleanup_attempted = threading.Event()
        allow_cleanup = threading.Event()

        class InterruptingLock:
            def __init__(self) -> None:
                self._lock = threading.Lock()
                self._interrupt = True

            def __enter__(self):
                if self._interrupt:
                    self._interrupt = False
                    raise interruption
                self._lock.acquire()
                return self

            def __exit__(self, *_args) -> None:
                self._lock.release()

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_processes.append(process)
            return process

        def fail_exact_cleanup(
            process_group: int,
            sent_signal: int,
        ) -> None:
            if not allow_cleanup.is_set():
                cleanup_attempted.set()
                raise OSError("synthetic persistent killpg failure")
            real_killpg(process_group, sent_signal)

        def release_cleanup() -> None:
            if cleanup_attempted.wait(timeout=2):
                time.sleep(0.1)
                allow_cleanup.set()

        executor._active_lock = InterruptingLock()
        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)"
        )
        releaser = threading.Thread(target=release_cleanup)
        releaser.start()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    runner_module.subprocess,
                    "Popen",
                    side_effect=recording_popen,
                ),
                mock.patch.object(
                    runner_module.os,
                    "killpg",
                    side_effect=fail_exact_cleanup,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                executor.run(
                    BuiltCommand((sys.executable, "-c", script), ""),
                    cwd=Path.cwd(),
                    timeout=30,
                    on_stdout_line=lambda _line: None,
                )

            elapsed = time.monotonic() - started
            self.assertIs(raised.exception, interruption)
            self.assertEqual(len(spawned_processes), 1)
            process = spawned_processes[0]
            self.assertGreaterEqual(elapsed, 0.09)
            self.assertFalse(Path(f"/proc/{process.pid}").exists())
            with executor._active_lock:
                self.assertEqual(executor._active_processes, {})
        finally:
            allow_cleanup.set()
            releaser.join(timeout=1)
            executor.cancel_active()

        self.assertFalse(releaser.is_alive())
        process = spawned_processes[0]
        self.assertFalse(Path(f"/proc/{process.pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_callback_interrupt_uses_retrying_exact_group_cleanup(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        interruption = KeyboardInterrupt(
            "synthetic stdout callback interrupt"
        )
        cleanup_started = threading.Event()
        spawned_pids: list[int] = []
        sent_signals: list[int] = []
        real_popen = runner_module.subprocess.Popen
        real_killpg = runner_module.os.killpg
        failed_poll = False
        failed_term = False

        def wrap_cleanup_poll(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned_pids.append(process.pid)
            real_poll = process.poll

            def poll():
                nonlocal failed_poll
                if cleanup_started.is_set() and not failed_poll:
                    failed_poll = True
                    raise OSError("synthetic one-shot cleanup poll error")
                return real_poll()

            process.poll = poll
            return process

        def fail_first_cleanup_term(
            process_group: int,
            sent_signal: int,
        ) -> None:
            nonlocal failed_term
            if sent_signal in {signal.SIGTERM, signal.SIGKILL}:
                sent_signals.append(sent_signal)
            if (
                cleanup_started.is_set()
                and sent_signal == signal.SIGTERM
                and not failed_term
            ):
                failed_term = True
                raise OSError("synthetic one-shot cleanup SIGTERM error")
            real_killpg(process_group, sent_signal)

        def interrupt_callback(_line: str | bytes) -> None:
            cleanup_started.set()
            raise interruption

        script = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print('callback',flush=True);"
            "time.sleep(30)"
        )
        with (
            mock.patch.object(
                runner_module.subprocess,
                "Popen",
                side_effect=wrap_cleanup_poll,
            ),
            mock.patch.object(
                runner_module.os,
                "killpg",
                side_effect=fail_first_cleanup_term,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=interrupt_callback,
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(failed_poll)
        self.assertEqual(sent_signals.count(signal.SIGTERM), 2)
        self.assertIn(signal.SIGKILL, sent_signals)
        self.assertEqual(len(spawned_pids), 1)
        self.assertFalse(Path(f"/proc/{spawned_pids[0]}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_callback_failure_survives_stream_close_and_final_poll_errors(
        self,
    ) -> None:
        for failure in (
            KeyboardInterrupt("synthetic callback interrupt"),
            FlagNotificationError("synthetic flag notification failure"),
        ):
            with self.subTest(failure=type(failure).__name__):
                executor = SubprocessExecutor(
                    terminate_grace_seconds=0.1,
                    drain_grace_seconds=0.1,
                )
                spawned_processes: list[subprocess.Popen[bytes]] = []
                real_popen = runner_module.subprocess.Popen
                close_failed = False
                post_wait_poll_attempts = 0

                class FirstCloseFails:
                    def __init__(self, stream) -> None:
                        self._stream = stream

                    def __getattr__(self, name):
                        return getattr(self._stream, name)

                    def close(self) -> None:
                        nonlocal close_failed
                        if not close_failed:
                            close_failed = True
                            raise OSError(
                                "synthetic one-shot stdout close failure"
                            )
                        self._stream.close()

                def wrap_process_stream(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    spawned_processes.append(process)
                    assert process.stdout is not None
                    process.stdout = FirstCloseFails(process.stdout)
                    real_wait = process.wait
                    real_poll = process.poll
                    reaped = False

                    def wait(*wait_args, **wait_kwargs):
                        nonlocal reaped
                        result = real_wait(*wait_args, **wait_kwargs)
                        reaped = True
                        return result

                    def poll():
                        nonlocal post_wait_poll_attempts
                        if reaped:
                            post_wait_poll_attempts += 1
                            raise OSError(
                                "synthetic post-cleanup poll failure"
                            )
                        return real_poll()

                    process.wait = wait
                    process.poll = poll
                    return process

                def fail_callback(_line: str | bytes) -> None:
                    raise failure

                script = (
                    "import signal,time;"
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                    "print('callback',flush=True);"
                    "time.sleep(30)"
                )
                with (
                    mock.patch.object(
                        runner_module.subprocess,
                        "Popen",
                        side_effect=wrap_process_stream,
                    ),
                    self.assertRaises(type(failure)) as raised,
                ):
                    executor.run(
                        BuiltCommand((sys.executable, "-c", script), ""),
                        cwd=Path.cwd(),
                        timeout=30,
                        on_stdout_line=fail_callback,
                    )

                self.assertIs(raised.exception, failure)
                self.assertTrue(close_failed)
                self.assertEqual(post_wait_poll_attempts, 0)
                self.assertTrue(
                    any(
                        "synthetic one-shot stdout close failure" in note
                        for note in failure.__notes__
                    )
                )
                self.assertEqual(len(spawned_processes), 1)
                process = spawned_processes[0]
                self.assertFalse(Path(f"/proc/{process.pid}").exists())
                with executor._active_lock:
                    self.assertEqual(executor._active_processes, {})

    def test_callback_failure_does_not_mask_first_cleanup_control(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.02,
            drain_grace_seconds=0.01,
        )
        callback_failure = FlagNotificationError(
            "synthetic flag notification failure"
        )
        interruption = KeyboardInterrupt(
            "synthetic callback cleanup interrupt"
        )
        real_terminate = executor._terminate_processes
        cleanup_calls = 0

        def fail_callback(_line: str | bytes) -> None:
            raise callback_failure

        def interrupt_then_cleanup(
            processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            if cleanup_calls == 1:
                raise interruption
            real_terminate(processes)

        script = "import time;print('callback',flush=True);time.sleep(30)"
        with (
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=interrupt_then_cleanup,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=fail_callback,
            )

        self.assertIs(raised.exception, interruption)
        self.assertGreaterEqual(cleanup_calls, 2)
        self.assertTrue(
            any(
                "synthetic flag notification failure" in note
                for note in interruption.__notes__
            )
        )
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})
            self.assertEqual(executor._pump_controls, {})

    def test_signal_interrupt_is_propagated_to_the_cleanup_retry_boundary(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic subprocess signal handoff interrupt"
        )
        term_attempts = 0

        class FinishedProcess:
            pid = 2_000_000_003
            stdin = None
            stdout = None
            stderr = None

            def __init__(self) -> None:
                self.waited = False

            def poll(self) -> int | None:
                return 0 if self.waited else None

            def wait(self, *, timeout: float) -> int:
                del timeout
                self.waited = True
                return 0

        def interrupt_then_disappear(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            nonlocal term_attempts
            if sent_signal == signal.SIGTERM:
                term_attempts += 1
                if term_attempts == 1:
                    raise interruption
            raise ProcessLookupError

        with (
            mock.patch.object(
                runner_module.os,
                "killpg",
                side_effect=interrupt_then_disappear,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor._terminate_processes(
                (FinishedProcess(),),  # type: ignore[arg-type]
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(term_attempts, 1)

    def test_uncertain_group_cleanup_preserves_first_signal_interrupt(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic uncertain-cleanup signal interrupt"
        )
        signal_attempts = 0

        class UncertainProcess:
            pid = 2_000_000_008
            stdin = None
            stdout = None
            stderr = None

            def poll(self) -> None:
                return None

            def wait(self, *, timeout: float) -> int:
                raise subprocess.TimeoutExpired(
                    ("synthetic",),
                    timeout,
                )

        def interrupt_then_deny(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            nonlocal signal_attempts
            if sent_signal == 0:
                return
            signal_attempts += 1
            if signal_attempts == 1:
                raise PermissionError("synthetic first signal denial")
            if signal_attempts == 2:
                raise interruption
            raise PermissionError("synthetic persistent signal denial")

        with (
            mock.patch.object(
                runner_module.os,
                "killpg",
                side_effect=interrupt_then_deny,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor._terminate_processes(
                (UncertainProcess(),),  # type: ignore[arg-type]
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(
            any(
                "first signal denial" in note
                for note in interruption.__notes__
            )
        )

    def test_cancel_active_retries_cleanup_before_propagating_control(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic active cancellation interrupt"
        )

        class RegisteredProcess:
            pid = 2_000_000_009

        process = RegisteredProcess()
        with executor._active_lock:
            executor._active_processes[process.pid] = (
                process,  # type: ignore[arg-type]
                None,
                object(),
            )

        cleanup_calls = 0

        def interrupt_then_confirm(
            _processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            if cleanup_calls == 1:
                raise interruption

        with (
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=interrupt_then_confirm,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.cancel_active()

        self.assertIs(raised.exception, interruption)
        self.assertEqual(cleanup_calls, 2)
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_reap_refreshes_the_final_process_group_identity(self) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.001,
            drain_grace_seconds=0.001,
        )

        class ReapedProcess:
            pid = 2_000_000_004
            stdin = None
            stdout = None
            stderr = None

            def __init__(self) -> None:
                self.waited = False

            def poll(self) -> int | None:
                return 0 if self.waited else None

            def wait(self, *, timeout: float) -> int:
                del timeout
                self.waited = True
                return 0

        process = ReapedProcess()

        def group_exists_until_wait(
            _process_group: int,
            sent_signal: int,
        ) -> None:
            if sent_signal == 0 and process.waited:
                raise ProcessLookupError

        with mock.patch.object(
            runner_module.os,
            "killpg",
            side_effect=group_exists_until_wait,
        ):
            executor._terminate_processes(
                (process,),  # type: ignore[arg-type]
            )

        self.assertTrue(process.waited)

    def test_persistent_cleanup_failure_blocks_owner_unwind_until_recovered(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic direct interruption"
        )
        persistent = RuntimeError("persistent exact-group cleanup failure")
        cleanup_attempted = threading.Event()
        allow_cleanup = threading.Event()

        class RegisteredProcess:
            pid = 2_000_000_005

        process = RegisteredProcess()

        def interrupt_registered_run(
            _command,
            *,
            cwd,
            timeout,
            on_stdout_line,
            cancel_event,
            owner_token,
        ):
            del cwd, timeout, on_stdout_line, cancel_event
            with executor._active_lock:
                executor._active_processes[process.pid] = (
                    process,  # type: ignore[arg-type]
                    None,
                    owner_token,
                )
            raise interruption

        def fail_until_released(
            _processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            if not allow_cleanup.is_set():
                cleanup_attempted.set()
                raise persistent

        def release_cleanup() -> None:
            if cleanup_attempted.wait(timeout=2):
                time.sleep(0.1)
                allow_cleanup.set()

        releaser = threading.Thread(target=release_cleanup)
        releaser.start()
        started = time.monotonic()
        with (
            mock.patch.object(
                executor,
                "_run_tracked",
                side_effect=interrupt_registered_run,
            ),
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=fail_until_released,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand(("unused",), ""),
                cwd=Path.cwd(),
                timeout=1,
                on_stdout_line=lambda _line: None,
            )

        releaser.join(timeout=1)
        elapsed = time.monotonic() - started
        self.assertIs(raised.exception, interruption)
        self.assertFalse(releaser.is_alive())
        self.assertGreaterEqual(elapsed, 0.09)
        self.assertTrue(
            any(
                "persistent exact-group cleanup failure" in note
                for note in interruption.__notes__
            )
        )
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_first_cleanup_control_interruption_is_preserved_after_recovery(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        body_error = RuntimeError("synthetic direct failure")
        interruption = SystemExit("synthetic first cleanup interruption")

        class RegisteredProcess:
            pid = 2_000_000_006

        process = RegisteredProcess()

        def fail_registered_run(
            _command,
            *,
            cwd,
            timeout,
            on_stdout_line,
            cancel_event,
            owner_token,
        ):
            del cwd, timeout, on_stdout_line, cancel_event
            with executor._active_lock:
                executor._active_processes[process.pid] = (
                    process,  # type: ignore[arg-type]
                    None,
                    owner_token,
                )
            raise body_error

        cleanup_calls = 0

        def interrupt_cleanup_once(
            _processes: tuple[subprocess.Popen[bytes], ...],
        ) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            if cleanup_calls == 1:
                raise interruption

        with (
            mock.patch.object(
                executor,
                "_run_tracked",
                side_effect=fail_registered_run,
            ),
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=interrupt_cleanup_once,
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            executor.run(
                BuiltCommand(("unused",), ""),
                cwd=Path.cwd(),
                timeout=1,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(cleanup_calls, 2)
        self.assertTrue(
            any(
                "synthetic direct failure" in note
                for note in interruption.__notes__
            )
        )
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_second_cleanup_control_interruption_retains_crash_only_owner(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.01,
            drain_grace_seconds=0.01,
        )
        interruption = KeyboardInterrupt(
            "synthetic direct interruption"
        )
        second_interruption = SystemExit(
            "synthetic second cleanup interruption"
        )

        class RegisteredProcess:
            pid = 2_000_000_007

        process = RegisteredProcess()

        def interrupt_registered_run(
            _command,
            *,
            cwd,
            timeout,
            on_stdout_line,
            cancel_event,
            owner_token,
        ):
            del cwd, timeout, on_stdout_line, cancel_event
            with executor._active_lock:
                executor._active_processes[process.pid] = (
                    process,  # type: ignore[arg-type]
                    None,
                    owner_token,
                )
            raise interruption

        with (
            mock.patch.object(
                executor,
                "_run_tracked",
                side_effect=interrupt_registered_run,
            ),
            mock.patch.object(
                executor,
                "_terminate_processes",
                side_effect=second_interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            executor.run(
                BuiltCommand(("unused",), ""),
                cwd=Path.cwd(),
                timeout=1,
                on_stdout_line=lambda _line: None,
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(
            any(
                "second SystemExit" in note
                for note in interruption.__notes__
            )
        )
        with executor._active_lock:
            self.assertEqual(
                tuple(executor._active_processes),
                (process.pid,),
            )
            executor._active_processes.clear()

    def test_direct_keyboard_interrupt_reaps_exact_process_and_forgets_owner(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        started = threading.Event()
        child_pids: list[int] = []

        def observe(line: str | bytes) -> None:
            payload = (
                line.decode("utf-8")
                if isinstance(line, bytes)
                else line
            )
            child_pids.append(int(payload.strip()))
            started.set()

        def interrupt_parent() -> None:
            if not started.wait(2):
                return
            time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGINT)

        interrupter = threading.Thread(
            target=interrupt_parent,
            name="ctfos-test-direct-interrupt",
            daemon=True,
        )
        interrupter.start()
        script = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print(os.getpid(),flush=True);"
            "time.sleep(30)"
        )
        try:
            with self.assertRaises(KeyboardInterrupt):
                executor.run(
                    BuiltCommand((sys.executable, "-c", script), ""),
                    cwd=Path.cwd(),
                    timeout=30,
                    on_stdout_line=observe,
                )
        finally:
            executor.cancel_active()
        interrupter.join(timeout=1)

        self.assertEqual(len(child_pids), 1)
        child_pid = child_pids[0]
        deadline = time.monotonic() + 1
        while (
            Path(f"/proc/{child_pid}").exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{child_pid}").exists())
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_scoped_cancel_does_not_terminate_another_wave(self) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )
        cancel_a = threading.Event()
        cancel_b = threading.Event()
        started_a = threading.Event()
        started_b = threading.Event()
        outcomes: dict[str, ProcessOutcome] = {}
        errors: list[BaseException] = []
        script = (
            "import time;"
            "print('started',flush=True);"
            "time.sleep(30)"
        )

        def run(
            label: str,
            cancel_event: threading.Event,
            started: threading.Event,
        ) -> None:
            try:
                outcomes[label] = executor.run(
                    BuiltCommand((sys.executable, "-c", script), ""),
                    cwd=Path.cwd(),
                    timeout=30,
                    on_stdout_line=lambda _line: started.set(),
                    cancel_event=cancel_event,
                )
            except BaseException as error:
                errors.append(error)

        thread_a = threading.Thread(
            target=run,
            args=("a", cancel_a, started_a),
        )
        thread_b = threading.Thread(
            target=run,
            args=("b", cancel_b, started_b),
        )
        thread_a.start()
        thread_b.start()
        try:
            self.assertTrue(started_a.wait(2))
            self.assertTrue(started_b.wait(2))

            cancel_a.set()
            executor.cancel_active(cancel_event=cancel_a)
            thread_a.join(timeout=2)

            self.assertFalse(thread_a.is_alive())
            self.assertTrue(thread_b.is_alive())
            self.assertNotEqual(outcomes["a"].returncode, 0)
        finally:
            cancel_b.set()
            executor.cancel_active(cancel_event=cancel_b)
            thread_a.join(timeout=2)
            thread_b.join(timeout=2)

        self.assertFalse(thread_b.is_alive())
        self.assertEqual(errors, [])
        self.assertNotEqual(outcomes["b"].returncode, 0)

    def test_large_stderr_is_drained_but_retained_only_to_explicit_cap(self) -> None:
        stdout_chunks: list[bytes | str] = []
        script = (
            "import sys;"
            "sys.stderr.buffer.write(b'e'*2000000);"
            "sys.stderr.flush();"
            "sys.stdout.buffer.write(b'done\\n');"
            "sys.stdout.flush()"
        )
        outcome = SubprocessExecutor(stderr_limit_bytes=1024).run(
            BuiltCommand((sys.executable, "-c", script), ""),
            cwd=Path.cwd(),
            timeout=5,
            on_stdout_line=stdout_chunks.append,
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.stderr_bytes, 2_000_000)
        self.assertTrue(outcome.stderr_truncated)
        self.assertLessEqual(len(outcome.stderr.encode("utf-8")), 1024)
        self.assertEqual(b"".join(stdout_chunks), b"done\n")

    def test_cancel_never_writes_stdin_to_reused_same_number_fd(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.05,
            drain_grace_seconds=0.01,
        )
        real_popen = runner_module.subprocess.Popen
        real_select = runner_module.select.select
        real_close_stream = runner_module._close_stream_bounded
        stdin_select_entered = threading.Event()
        foreign_ready = threading.Event()
        captured: dict[str, object] = {}
        outcomes: list[ProcessOutcome] = []
        run_errors: list[BaseException] = []

        with tempfile.TemporaryDirectory() as temporary:
            foreign_path = Path(temporary) / "foreign-stdin"

            def capture_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                assert process.stdin is not None
                captured["process"] = process
                captured["stdin_fd"] = process.stdin.fileno()
                return process

            def wait_for_cancel_before_writable(
                readable,
                writable,
                exceptional,
                timeout=None,
            ):
                stdin_fd = captured.get("stdin_fd")
                if (
                    not readable
                    and writable
                    and writable[0] == stdin_fd
                ):
                    stdin_select_entered.set()
                    deadline = time.monotonic() + 5
                    while not foreign_ready.is_set():
                        process = captured.get("process")
                        controls = getattr(
                            executor,
                            "_pump_controls",
                            {},
                        )
                        owned = (
                            controls.get(process.pid)
                            if process is not None
                            else None
                        )
                        if (
                            owned is not None
                            and owned[1].stdin_stop.is_set()
                        ):
                            return (), (writable[0],), ()
                        if time.monotonic() >= deadline:
                            raise RuntimeError(
                                "stdin cancellation handoff timed out"
                            )
                        foreign_ready.wait(0.005)
                    return (), (writable[0],), ()
                return real_select(
                    readable,
                    writable,
                    exceptional,
                    timeout,
                )

            def close_then_reuse(stream, *, label):
                result = real_close_stream(stream, label=label)
                process = captured.get("process")
                if (
                    label == "stdin"
                    and process is not None
                    and stream is process.stdin
                    and not foreign_ready.is_set()
                ):
                    stdin_fd = captured["stdin_fd"]
                    assert isinstance(stdin_fd, int)
                    source_fd = os.open(
                        foreign_path,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_TRUNC
                        | os.O_CLOEXEC,
                        0o600,
                    )
                    captured["foreign_source_fd"] = source_fd
                    if source_fd != stdin_fd:
                        os.dup2(
                            source_fd,
                            stdin_fd,
                            inheritable=False,
                        )
                    captured["foreign_fd"] = stdin_fd
                    foreign_ready.set()
                return result

            def run_process() -> None:
                try:
                    outcomes.append(
                        executor.run(
                            BuiltCommand(
                                (
                                    sys.executable,
                                    "-c",
                                    "import time;time.sleep(30)",
                                ),
                                "CROSS_CALL_PROMPT\n",
                            ),
                            cwd=Path.cwd(),
                            timeout=30,
                            on_stdout_line=lambda _chunk: None,
                        )
                    )
                except BaseException as error:
                    run_errors.append(error)

            worker = threading.Thread(
                target=run_process,
                name="ctfos-test-stdin-reuse",
                daemon=True,
            )
            try:
                with (
                    mock.patch.object(
                        runner_module.subprocess,
                        "Popen",
                        side_effect=capture_popen,
                    ),
                    mock.patch.object(
                        runner_module.select,
                        "select",
                        side_effect=wait_for_cancel_before_writable,
                    ),
                    mock.patch.object(
                        runner_module,
                        "_close_stream_bounded",
                        side_effect=close_then_reuse,
                    ),
                ):
                    worker.start()
                    self.assertTrue(stdin_select_entered.wait(5))
                    executor.cancel_active()
                    worker.join(5)

                self.assertFalse(worker.is_alive())
                self.assertEqual(run_errors, [])
                self.assertEqual(len(outcomes), 1)
                self.assertTrue(foreign_ready.is_set())
                foreign_fd = captured["foreign_fd"]
                assert isinstance(foreign_fd, int)
                os.fstat(foreign_fd)
                self.assertEqual(foreign_path.read_bytes(), b"")
                with executor._active_lock:
                    self.assertEqual(executor._active_processes, {})
                    self.assertEqual(executor._pump_controls, {})
            finally:
                foreign_ready.set()
                if worker.is_alive():
                    executor.cancel_active()
                    worker.join(2)
                for name in ("foreign_fd", "foreign_source_fd"):
                    descriptor = captured.get(name)
                    if isinstance(descriptor, int):
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass

    def test_cancel_never_reads_stdout_from_reused_same_number_fd(
        self,
    ) -> None:
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.05,
            drain_grace_seconds=0.01,
        )
        real_popen = runner_module.subprocess.Popen
        real_read = runner_module.os.read
        real_close_stream = runner_module._close_stream_bounded
        stdout_read_entered = threading.Event()
        foreign_ready = threading.Event()
        captured: dict[str, object] = {}
        stdout_chunks: list[bytes | str] = []
        outcomes: list[ProcessOutcome] = []
        run_errors: list[BaseException] = []
        foreign_payload = b"FLAG{foreign_stdout_aba}\n"

        def capture_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            assert process.stdout is not None
            captured["process"] = process
            captured["stdout_fd"] = process.stdout.fileno()
            return process

        def wait_for_cancel_before_read(
            descriptor: int,
            maximum: int,
        ) -> bytes:
            if descriptor != captured.get("stdout_fd"):
                return real_read(descriptor, maximum)
            stdout_read_entered.set()
            deadline = time.monotonic() + 5
            while not foreign_ready.is_set():
                process = captured.get("process")
                controls = getattr(executor, "_pump_controls", {})
                owned = (
                    controls.get(process.pid)
                    if process is not None
                    else None
                )
                if (
                    owned is not None
                    and owned[1].output_stop.is_set()
                ):
                    return b""
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "stdout cancellation handoff timed out"
                    )
                foreign_ready.wait(0.005)
            return real_read(descriptor, maximum)

        def close_then_reuse(stream, *, label):
            result = real_close_stream(stream, label=label)
            process = captured.get("process")
            if (
                label == "stdout"
                and process is not None
                and stream is process.stdout
                and not foreign_ready.is_set()
            ):
                stdout_fd = captured["stdout_fd"]
                assert isinstance(stdout_fd, int)
                source_fd, writer_fd = os.pipe()
                try:
                    os.write(writer_fd, foreign_payload)
                finally:
                    os.close(writer_fd)
                captured["foreign_source_fd"] = source_fd
                if source_fd != stdout_fd:
                    os.dup2(
                        source_fd,
                        stdout_fd,
                        inheritable=False,
                    )
                captured["foreign_fd"] = stdout_fd
                foreign_ready.set()
            return result

        def run_process() -> None:
            try:
                outcomes.append(
                    executor.run(
                        BuiltCommand(
                            (
                                sys.executable,
                                "-c",
                                (
                                    "import sys,time;"
                                    "sys.stdout.write('original\\n');"
                                    "sys.stdout.flush();"
                                    "time.sleep(30)"
                                ),
                            ),
                            "",
                        ),
                        cwd=Path.cwd(),
                        timeout=30,
                        on_stdout_line=stdout_chunks.append,
                    )
                )
            except BaseException as error:
                run_errors.append(error)

        worker = threading.Thread(
            target=run_process,
            name="ctfos-test-stdout-reuse",
            daemon=True,
        )
        try:
            with (
                mock.patch.object(
                    runner_module.subprocess,
                    "Popen",
                    side_effect=capture_popen,
                ),
                mock.patch.object(
                    runner_module.os,
                    "read",
                    side_effect=wait_for_cancel_before_read,
                ),
                mock.patch.object(
                    runner_module,
                    "_close_stream_bounded",
                    side_effect=close_then_reuse,
                ),
            ):
                worker.start()
                self.assertTrue(stdout_read_entered.wait(5))
                executor.cancel_active()
                worker.join(5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(run_errors, [])
            self.assertEqual(len(outcomes), 1)
            self.assertTrue(foreign_ready.is_set())
            self.assertNotIn(
                foreign_payload,
                b"".join(
                    chunk.encode("utf-8")
                    if isinstance(chunk, str)
                    else chunk
                    for chunk in stdout_chunks
                ),
            )
            foreign_fd = captured["foreign_fd"]
            assert isinstance(foreign_fd, int)
            self.assertEqual(
                os.read(foreign_fd, len(foreign_payload)),
                foreign_payload,
            )
            with executor._active_lock:
                self.assertEqual(executor._active_processes, {})
                self.assertEqual(executor._pump_controls, {})
        finally:
            foreign_ready.set()
            if worker.is_alive():
                executor.cancel_active()
                worker.join(2)
            for name in ("foreign_fd", "foreign_source_fd"):
                descriptor = captured.get(name)
                if isinstance(descriptor, int):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def test_timeout_includes_nonreading_child_stdin(self) -> None:
        started = time.monotonic()
        outcome = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        ).run(
            BuiltCommand(
                (sys.executable, "-c", "import time;time.sleep(30)"),
                "x" * (8 * 1024 * 1024),
            ),
            cwd=Path.cwd(),
            timeout=0.1,
            on_stdout_line=lambda _chunk: None,
        )

        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(outcome.timed_out)
        self.assertNotEqual(outcome.returncode, 0)

    def test_pre_cancelled_start_kills_sigterm_ignoring_process(self) -> None:
        cancel_event = threading.Event()
        cancel_event.set()
        previous_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        started = time.monotonic()
        try:
            outcome = SubprocessExecutor(
                terminate_grace_seconds=0.1,
                drain_grace_seconds=0.1,
            ).run(
                BuiltCommand(
                    (sys.executable, "-c", "import time;time.sleep(30)"),
                    "",
                ),
                cwd=Path.cwd(),
                timeout=30,
                on_stdout_line=lambda _chunk: None,
                cancel_event=cancel_event,
            )
        finally:
            signal.signal(signal.SIGTERM, previous_handler)

        self.assertLess(time.monotonic() - started, 1)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.returncode, -signal.SIGKILL)

    def test_large_bidirectional_output_before_stdin_read_does_not_deadlock(
        self,
    ) -> None:
        stdout_chunks: list[bytes | str] = []
        chunk_count = 32
        chunk_bytes = 64 * 1024
        script = (
            "import os,sys;"
            f"chunk=b'o'*{chunk_bytes};"
            f"[(os.write(1,chunk),os.write(2,chunk)) "
            f"for _ in range({chunk_count})];"
            "data=sys.stdin.buffer.read();"
            "sys.stdout.write(f'\\nstdin={len(data)}\\n');"
            "sys.stdout.flush()"
        )
        stdin_bytes = 4 * 1024 * 1024
        outcome = SubprocessExecutor(stderr_limit_bytes=1024).run(
            BuiltCommand(
                (sys.executable, "-c", script),
                "i" * stdin_bytes,
            ),
            cwd=Path.cwd(),
            timeout=5,
            on_stdout_line=stdout_chunks.append,
        )

        stdout = b"".join(stdout_chunks)
        self.assertEqual(outcome.returncode, 0)
        self.assertFalse(outcome.timed_out)
        self.assertTrue(outcome.stdout_capture_complete)
        self.assertTrue(outcome.stderr_capture_complete)
        self.assertEqual(
            outcome.stderr_bytes,
            chunk_count * chunk_bytes,
        )
        self.assertTrue(
            stdout.endswith(f"\nstdin={stdin_bytes}\n".encode("ascii"))
        )

    def test_timeout_terminates_codex_process_group(self) -> None:
        child_pids: list[int] = []
        script = (
            "import subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c',"
            "'import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)']);"
            "print(p.pid,flush=True);"
            "time.sleep(30)"
        )
        outcome = SubprocessExecutor().run(
            BuiltCommand((sys.executable, "-c", script), ""),
            cwd=Path.cwd(),
            timeout=0.1,
            on_stdout_line=lambda line: child_pids.append(int(line.strip())),
        )
        self.assertTrue(outcome.timed_out)
        self.assertNotEqual(outcome.returncode, 0)
        self.assertEqual(len(child_pids), 1)
        deadline = time.monotonic() + 1
        state = None
        while time.monotonic() < deadline:
            try:
                stat = Path(f"/proc/{child_pids[0]}/stat").read_text(encoding="utf-8")
            except FileNotFoundError:
                state = None
                break
            state = stat[stat.rfind(")") + 2 :].split()[0]
            if state == "Z":
                break
            time.sleep(0.01)
        self.assertIn(state, (None, "Z"))

    def test_timeout_does_not_wait_for_detached_pipe_holder(self) -> None:
        child_pids: list[int] = []
        script = (
            "import subprocess,sys,time;"
            "p=subprocess.Popen("
            "[sys.executable,'-c','import time;time.sleep(30)'],"
            "start_new_session=True,stdout=sys.stdout,stderr=sys.stderr"
            ");"
            "print(p.pid,flush=True);"
            "time.sleep(30)"
        )
        started = time.monotonic()
        try:
            outcome = SubprocessExecutor(
                terminate_grace_seconds=0.1,
                drain_grace_seconds=0.2,
            ).run(
                BuiltCommand(
                    (sys.executable, "-c", script),
                    "x" * (4 * 1024 * 1024),
                ),
                cwd=Path.cwd(),
                timeout=0.1,
                on_stdout_line=lambda line: child_pids.append(
                    int(line.strip())
                ),
            )
        finally:
            for child_pid in child_pids:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(outcome.timed_out)
        self.assertFalse(outcome.stdout_capture_complete)
        self.assertFalse(outcome.stderr_capture_complete)

    def test_normal_exit_reaps_same_group_pipe_holder(self) -> None:
        child_pids: list[int] = []
        script = (
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c',"
            "'import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)'],"
            "stdout=sys.stdout,stderr=sys.stderr);"
            "print(p.pid,flush=True)"
        )
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )

        outcome = executor.run(
            BuiltCommand((sys.executable, "-c", script), ""),
            cwd=Path.cwd(),
            timeout=5,
            on_stdout_line=lambda line: child_pids.append(
                int(line.strip())
            ),
        )

        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.returncode, 125)
        self.assertFalse(outcome.stdout_capture_complete)
        self.assertFalse(outcome.stderr_capture_complete)
        self.assertEqual(len(child_pids), 1)
        deadline = time.monotonic() + 1
        state = None
        while time.monotonic() < deadline:
            try:
                stat = Path(
                    f"/proc/{child_pids[0]}/stat"
                ).read_text(encoding="utf-8")
            except FileNotFoundError:
                state = None
                break
            state = stat[stat.rfind(")") + 2 :].split()[0]
            if state == "Z":
                break
            time.sleep(0.01)
        self.assertIn(state, (None, "Z"))
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_normal_exit_reaps_same_group_child_with_closed_output(
        self,
    ) -> None:
        child_pids: list[int] = []
        script = (
            "import subprocess,sys;"
            "p=subprocess.Popen([sys.executable,'-c',"
            "'import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(30)'],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "print(p.pid,flush=True)"
        )
        executor = SubprocessExecutor(
            terminate_grace_seconds=0.1,
            drain_grace_seconds=0.1,
        )

        outcome = executor.run(
            BuiltCommand((sys.executable, "-c", script), ""),
            cwd=Path.cwd(),
            timeout=5,
            on_stdout_line=lambda line: child_pids.append(
                int(line.strip())
            ),
        )

        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.returncode, 0)
        self.assertTrue(outcome.stdout_capture_complete)
        self.assertTrue(outcome.stderr_capture_complete)
        self.assertEqual(len(child_pids), 1)
        deadline = time.monotonic() + 1
        state = None
        while time.monotonic() < deadline:
            try:
                stat = Path(
                    f"/proc/{child_pids[0]}/stat"
                ).read_text(encoding="utf-8")
            except FileNotFoundError:
                state = None
                break
            state = stat[stat.rfind(")") + 2 :].split()[0]
            if state == "Z":
                break
            time.sleep(0.01)
        self.assertIn(state, (None, "Z"))
        with executor._active_lock:
            self.assertEqual(executor._active_processes, {})

    def test_normal_exit_does_not_wait_for_detached_pipe_holder(self) -> None:
        child_pids: list[int] = []
        script = (
            "import subprocess,sys;"
            "p=subprocess.Popen("
            "[sys.executable,'-c','import time;time.sleep(30)'],"
            "start_new_session=True,stdout=sys.stdout,stderr=sys.stderr"
            ");"
            "print(p.pid,flush=True)"
        )
        started = time.monotonic()
        try:
            outcome = SubprocessExecutor(
                terminate_grace_seconds=0.1,
                drain_grace_seconds=0.2,
            ).run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=5,
                on_stdout_line=lambda line: child_pids.append(
                    int(line.strip())
                ),
            )
        finally:
            for child_pid in child_pids:
                try:
                    os.killpg(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(outcome.returncode, 125)
        self.assertFalse(outcome.stdout_capture_complete)
        self.assertFalse(outcome.stderr_capture_complete)


if __name__ == "__main__":
    unittest.main()
