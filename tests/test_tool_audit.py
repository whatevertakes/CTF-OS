from __future__ import annotations

from pathlib import Path

from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.tool_audit import run_tool_audit


def test_tool_audit_contracts_match_repository_sources() -> None:
    result = run_tool_audit(Path(".").resolve())
    assert result["ok"] is True, result["errors"]
    assert result["upstream_checked"] is False
    assert len(result["contracts"]) >= 35
    assert all(contract["matched"] for contract in result["contracts"])


def test_tool_audit_cli_exposes_explicit_network_check() -> None:
    args = build_parser().parse_args(["tool-audit", "--check-upstream"])
    assert args.command == "tool-audit"
    assert args.check_upstream is True


def test_tool_audit_reports_upstream_transport_failures_without_crashing() -> None:
    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise OSError("rate limited")

    result = run_tool_audit(
        Path(".").resolve(),
        check_upstream=True,
        opener=unavailable,
    )
    assert result["ok"] is False
    assert result["upstream_checked"] is True
    assert result["upstream"]
    assert all(item["latest"] is None for item in result["upstream"])
    assert all("error" in item for item in result["upstream"])
