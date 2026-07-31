from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch

from ctf_os.knowledge import (
    MAX_EXTRACTED_TEXT_BYTES,
    MAX_KNOWLEDGE_READ_BYTES,
    MAX_KNOWLEDGE_SEARCH_RESULTS,
)
from ctf_os.live_broker import (
    MAX_INSPECT_OFFSET,
    MAX_INSPECT_PAGE_ITEMS,
)
from ctf_os.live_mcp import (
    MAX_MCP_MESSAGE_BYTES,
    LiveMCPServer,
    main,
)
from ctf_os.models import ChallengeIdentity


class _FakeBrokerClient:
    def __init__(self, result: object | None = None) -> None:
        self.result = {"ok": True} if result is None else result
        self.calls: list[
            tuple[str, ChallengeIdentity, dict[str, object]]
        ] = []

    def call(self, operation, identity, params=None, *, timeout=0):
        del timeout
        self.calls.append((operation, identity, dict(params or {})))
        return self.result


def _messages(*values: object) -> io.BytesIO:
    return io.BytesIO(
        b"".join(
            (
                json.dumps(value, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            for value in values
        )
    )


def _responses(output: io.BytesIO) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in output.getvalue().decode("utf-8").splitlines()
    ]


class LiveMCPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = ChallengeIdentity("contest", "pwn", "warmup")

    def test_handshake_lists_only_typed_tools_and_forwards_scoped_call(
        self,
    ) -> None:
        client = _FakeBrokerClient({"facts": []})
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        status = server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "inspect",
                        "arguments": {"section": "facts"},
                    },
                },
            ),
            output,
        )

        self.assertEqual(status, 0)
        responses = _responses(output)
        self.assertEqual([item["id"] for item in responses], [1, 2, 3])
        initialize = responses[0]["result"]
        self.assertEqual(initialize["protocolVersion"], "2025-06-18")
        self.assertEqual(
            initialize["capabilities"], {"tools": {"listChanged": False}}
        )
        tools = responses[1]["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertEqual(
            names,
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
                "tool.run",
                "tool.start",
                "jobs",
                "inspect",
                "knowledge.search",
                "knowledge.read",
            },
        )
        self.assertNotIn("submit", " ".join(names))
        self.assertNotIn("shell", " ".join(names))
        transition = next(
            tool for tool in tools if tool["name"] == "agent.transition"
        )
        targets = transition["inputSchema"]["properties"]["target"]["enum"]
        self.assertEqual(
            targets,
            [
                "TRIAGING",
                "ACTIVE",
                "STALLED",
                "NEEDS_RESEARCH",
                "NEEDS_HUMAN",
                "PAUSED",
            ],
        )
        self.assertNotIn("ABANDONED", targets)
        self.assertNotIn("PROVING", targets)
        self.assertNotIn("READY_TO_SUBMIT", targets)
        self.assertNotIn("SOLVED", targets)
        fact = next(tool for tool in tools if tool["name"] == "agent.fact")
        provenances = fact["inputSchema"]["properties"]["provenance"]["enum"]
        self.assertEqual(provenances, ["model_claimed"])
        artifact = next(
            tool for tool in tools if tool["name"] == "agent.artifact"
        )
        self.assertEqual(
            set(artifact["inputSchema"]["properties"]),
            {"locator"},
        )
        inspect = next(tool for tool in tools if tool["name"] == "inspect")
        inspect_properties = inspect["inputSchema"]["properties"]
        self.assertIn(
            "summary",
            inspect_properties["section"]["enum"],
        )
        self.assertIn(
            "progress_markers",
            inspect_properties["section"]["enum"],
        )
        self.assertEqual(
            inspect_properties["offset"]["maximum"],
            MAX_INSPECT_OFFSET,
        )
        self.assertEqual(
            inspect_properties["limit"]["maximum"],
            MAX_INSPECT_PAGE_ITEMS,
        )
        knowledge_search = next(
            tool for tool in tools if tool["name"] == "knowledge.search"
        )
        self.assertTrue(knowledge_search["annotations"]["readOnlyHint"])
        self.assertEqual(
            knowledge_search["inputSchema"]["properties"]["limit"]["maximum"],
            MAX_KNOWLEDGE_SEARCH_RESULTS,
        )
        knowledge_read = next(
            tool for tool in tools if tool["name"] == "knowledge.read"
        )
        self.assertTrue(knowledge_read["annotations"]["readOnlyHint"])
        self.assertEqual(
            knowledge_read["inputSchema"]["properties"]["max_bytes"]["maximum"],
            MAX_KNOWLEDGE_READ_BYTES,
        )
        self.assertEqual(
            knowledge_read["inputSchema"]["properties"]["offset_bytes"][
                "maximum"
            ],
            MAX_EXTRACTED_TEXT_BYTES,
        )
        self.assertEqual(
            client.calls,
            [("inspect", self.identity, {"section": "facts"})],
        )
        tool_result = responses[2]["result"]
        self.assertFalse(tool_result["isError"])
        self.assertEqual(
            tool_result["structuredContent"],
            {"result": {"facts": []}},
        )

    def test_tool_run_is_only_forwarded_as_typed_broker_operation(self) -> None:
        client = _FakeBrokerClient({"experiment_id": "exp-1"})
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        arguments = {
            "command": ["python3", "/challenge/solve.py"],
            "expected_observation": "candidate appears",
            "keep_if": "candidate is stable",
            "drop_if": "candidate disappears",
            "hypothesis_ids": ["hyp-1"],
            "timeout_seconds": 30,
            "resource_class": "light",
            "needs_kvm": False,
        }
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "tool.run",
                        "arguments": arguments,
                    },
                },
            ),
            output,
        )
        self.assertEqual(
            client.calls,
            [("tool.run", self.identity, arguments)],
        )
        self.assertFalse(_responses(output)[1]["result"]["isError"])

    def test_knowledge_tools_are_strict_read_only_broker_operations(self) -> None:
        client = _FakeBrokerClient({"schema_version": 1, "results": []})
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        document_id = "K-" + "a" * 32
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "knowledge.search",
                        "arguments": {"query": "heap unlink", "limit": 3},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "knowledge.read",
                        "arguments": {
                            "document_id": document_id,
                            "offset_bytes": 128,
                            "max_bytes": 4096,
                        },
                    },
                },
            ),
            output,
        )
        self.assertEqual(
            client.calls,
            [
                (
                    "knowledge.search",
                    self.identity,
                    {"query": "heap unlink", "limit": 3},
                ),
                (
                    "knowledge.read",
                    self.identity,
                    {
                        "document_id": document_id,
                        "offset_bytes": 128,
                        "max_bytes": 4096,
                    },
                ),
            ],
        )
        self.assertFalse(_responses(output)[1]["result"]["isError"])
        self.assertFalse(_responses(output)[2]["result"]["isError"])

        invalid_client = _FakeBrokerClient()
        invalid_output = io.BytesIO()
        LiveMCPServer(invalid_client, self.identity).serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "knowledge.read",
                        "arguments": {
                            "document_id": document_id,
                            "max_bytes": MAX_KNOWLEDGE_READ_BYTES + 1,
                        },
                    },
                },
            ),
            invalid_output,
        )
        self.assertEqual(invalid_client.calls, [])
        self.assertTrue(_responses(invalid_output)[1]["result"]["isError"])

    def test_typed_closed_loop_tools_validate_and_forward_exact_fields(
        self,
    ) -> None:
        client = _FakeBrokerClient({"status": "open"})
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        hypothesis_arguments = {
            "action": "create",
            "hypothesis_id": "H-live",
            "statement": "the parser truncates at NUL",
            "falsifier": "run a non-NUL control",
            "status": "open",
            "evidence_fact_ids": [],
            "evidence_artifact_ids": [],
            "evidence_run_ids": [],
            "confidence": 0.4,
        }
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.hypothesis",
                        "arguments": hypothesis_arguments,
                    },
                },
            ),
            output,
        )
        self.assertEqual(
            client.calls,
            [
                (
                    "agent.hypothesis",
                    self.identity,
                    hypothesis_arguments,
                )
            ],
        )
        self.assertFalse(_responses(output)[1]["result"]["isError"])

        invalid_client = _FakeBrokerClient()
        invalid_server = LiveMCPServer(invalid_client, self.identity)
        invalid_output = io.BytesIO()
        invalid_server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.hypothesis",
                        "arguments": {
                            **hypothesis_arguments,
                            "confidence": 1.1,
                        },
                    },
                },
            ),
            invalid_output,
        )
        self.assertEqual(invalid_client.calls, [])
        self.assertTrue(
            _responses(invalid_output)[1]["result"]["isError"]
        )

    def test_invalid_arguments_are_tool_errors_and_never_reach_broker(
        self,
    ) -> None:
        client = _FakeBrokerClient()
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "inspect",
                        "arguments": {
                            "section": "facts",
                            "command": ["sh", "-c", "id"],
                        },
                    },
                },
            ),
            output,
        )
        self.assertEqual(client.calls, [])
        response = _responses(output)[1]
        self.assertTrue(response["result"]["isError"])
        self.assertIn(
            "unexpected arguments",
            response["result"]["content"][0]["text"],
        )

    def test_inspect_pagination_arguments_validate_and_forward(self) -> None:
        valid_client = _FakeBrokerClient({"items": [], "total": 0})
        valid_output = io.BytesIO()
        LiveMCPServer(valid_client, self.identity).serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "inspect",
                        "arguments": {
                            "section": "runs",
                            "offset": 4,
                            "limit": 2,
                        },
                    },
                },
            ),
            valid_output,
        )
        self.assertEqual(
            valid_client.calls,
            [
                (
                    "inspect",
                    self.identity,
                    {"section": "runs", "offset": 4, "limit": 2},
                )
            ],
        )
        self.assertFalse(_responses(valid_output)[1]["result"]["isError"])

        invalid_arguments = (
            {"section": "runs", "offset": -1},
            {"section": "runs", "offset": True},
            {"section": "runs", "offset": 1.5},
            {
                "section": "runs",
                "offset": MAX_INSPECT_OFFSET + 1,
            },
            {"section": "runs", "limit": 0},
            {"section": "runs", "limit": True},
            {"section": "runs", "limit": 1.5},
            {
                "section": "runs",
                "limit": MAX_INSPECT_PAGE_ITEMS + 1,
            },
        )
        invalid_client = _FakeBrokerClient()
        calls = [
            {
                "jsonrpc": "2.0",
                "id": index + 2,
                "method": "tools/call",
                "params": {
                    "name": "inspect",
                    "arguments": arguments,
                },
            }
            for index, arguments in enumerate(invalid_arguments)
        ]
        invalid_output = io.BytesIO()
        LiveMCPServer(invalid_client, self.identity).serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                *calls,
            ),
            invalid_output,
        )
        self.assertEqual(invalid_client.calls, [])
        self.assertTrue(
            all(
                response["result"]["isError"]
                for response in _responses(invalid_output)[1:]
            )
        )

    def test_proof_transition_is_rejected_before_broker(self) -> None:
        client = _FakeBrokerClient()
        server = LiveMCPServer(client, self.identity)
        output = io.BytesIO()
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.transition",
                        "arguments": {"target": "PROVING"},
                    },
                },
            ),
            output,
        )
        self.assertEqual(client.calls, [])
        response = _responses(output)[1]
        self.assertTrue(response["result"]["isError"])
        self.assertIn(
            "not an allowed value",
            response["result"]["content"][0]["text"],
        )

    def test_non_open_hypothesis_status_is_rejected_before_broker(
        self,
    ) -> None:
        client = _FakeBrokerClient()
        output = io.BytesIO()
        LiveMCPServer(client, self.identity).serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.hypothesis",
                        "arguments": {
                            "action": "update",
                            "hypothesis_id": "H-existing",
                            "status": "confirmed",
                        },
                    },
                },
            ),
            output,
        )

        self.assertEqual(client.calls, [])
        response = _responses(output)[1]
        self.assertTrue(response["result"]["isError"])
        self.assertIn(
            "not an allowed value",
            response["result"]["content"][0]["text"],
        )

    def test_operator_fact_and_abandoned_transition_are_rejected_before_broker(
        self,
    ) -> None:
        client = _FakeBrokerClient()
        output = io.BytesIO()
        LiveMCPServer(client, self.identity).serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.fact",
                        "arguments": {
                            "statement": "model assertion",
                            "provenance": "operator",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.transition",
                        "arguments": {"target": "ABANDONED"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.fact",
                        "arguments": {
                            "statement": "bounded model assertion",
                            "provenance": "model_claimed",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.transition",
                        "arguments": {"target": "ACTIVE"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.artifact",
                        "arguments": {
                            "locator": "solver.py",
                            "source_run_id": "run-model-chosen",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.artifact",
                        "arguments": {"locator": "solver.py"},
                    },
                },
            ),
            output,
        )

        responses = _responses(output)
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertTrue(responses[2]["result"]["isError"])
        self.assertFalse(responses[3]["result"]["isError"])
        self.assertFalse(responses[4]["result"]["isError"])
        self.assertTrue(responses[5]["result"]["isError"])
        self.assertFalse(responses[6]["result"]["isError"])
        self.assertEqual(
            client.calls,
            [
                (
                    "agent.fact",
                    self.identity,
                    {
                        "statement": "bounded model assertion",
                        "provenance": "model_claimed",
                    },
                ),
                (
                    "agent.transition",
                    self.identity,
                    {"target": "ACTIVE"},
                ),
                (
                    "agent.artifact",
                    self.identity,
                    {"locator": "solver.py"},
                ),
            ],
        )

    def test_input_and_output_are_hard_bounded(self) -> None:
        oversized_input = (
            b'{"jsonrpc":"2.0","id":9,"method":"'
            + b"x" * MAX_MCP_MESSAGE_BYTES
            + b'"}\n'
        )
        initialize = _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        ).getvalue()
        output = io.BytesIO()
        LiveMCPServer(_FakeBrokerClient(), self.identity).serve(
            io.BytesIO(oversized_input + initialize),
            output,
        )
        responses = _responses(output)
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertEqual(responses[1]["id"], 1)
        self.assertTrue(
            all(
                len(line) <= MAX_MCP_MESSAGE_BYTES
                for line in output.getvalue().splitlines()
            )
        )

        large_result = "x" * MAX_MCP_MESSAGE_BYTES
        server = LiveMCPServer(_FakeBrokerClient(large_result), self.identity)
        output = io.BytesIO()
        server.serve(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "inspect",
                        "arguments": {"section": "state"},
                    },
                },
            ),
            output,
        )
        response = _responses(output)[1]
        self.assertEqual(response["error"]["code"], -32603)
        self.assertLessEqual(
            max(len(line) for line in output.getvalue().splitlines()),
            MAX_MCP_MESSAGE_BYTES,
        )

    def test_entrypoint_refuses_missing_scope_without_local_fallback(self) -> None:
        stderr = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("sys.stderr", stderr),
        ):
            self.assertEqual(main(), 2)
        self.assertIn("no local fallback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
