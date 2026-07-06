#!/usr/bin/env python3
"""Functionally probe configured CTF MCP servers through stdio."""

from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / ".codex" / "config.toml"
SMOKE_BINARY = Path("/bin/true")
REQUIRED_SERVERS = ("angr", "playwright", "radare2")


def load_servers() -> dict[str, dict[str, Any]]:
    config = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    servers = config.get("mcp_servers")
    if not isinstance(servers, dict):
        raise ValueError("mcp_servers is missing from .codex/config.toml")
    return servers


def server_parameters(name: str, config: dict[str, Any]) -> StdioServerParameters:
    command = config.get("command")
    args = config.get("args", [])
    configured_env = config.get("env", {})
    if not isinstance(command, str) or not command:
        raise ValueError(f"{name}: command must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ValueError(f"{name}: args must be a list of strings")
    if not isinstance(configured_env, dict):
        raise ValueError(f"{name}: env must be a mapping")
    env = dict(os.environ)
    env.update({str(key): str(value) for key, value in configured_env.items()})
    return StdioServerParameters(command=command, args=args, env=env)


def result_text(result: Any) -> str:
    return "\n".join(
        str(item.text)
        for item in result.content
        if hasattr(item, "text")
    )


async def require_tools(session: ClientSession, name: str, required: set[str]) -> None:
    response = await session.list_tools()
    available = {tool.name for tool in response.tools}
    missing = sorted(required - available)
    if missing:
        raise RuntimeError(f"{name}: missing MCP tools: {', '.join(missing)}")


async def probe_angr(session: ClientSession) -> None:
    await require_tools(session, "angr", {"load_binary", "close_project"})
    result = await session.call_tool(
        "load_binary",
        {"binary_path": str(SMOKE_BINARY), "auto_load_libs": False},
    )
    if result.isError:
        raise RuntimeError(f"angr load_binary failed: {result_text(result)}")
    payload = json.loads(result_text(result))
    project_id = payload.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        raise RuntimeError("angr load_binary returned no project_id")
    closed = await session.call_tool("close_project", {"project_id": project_id})
    if closed.isError:
        raise RuntimeError(f"angr close_project failed: {result_text(closed)}")


async def probe_playwright(session: ClientSession) -> None:
    await require_tools(session, "playwright", {"browser_tabs"})
    result = await session.call_tool("browser_tabs", {"action": "list"})
    if result.isError:
        raise RuntimeError(f"playwright browser launch failed: {result_text(result)}")
    if "about:blank" not in result_text(result):
        raise RuntimeError("playwright browser_tabs returned no active blank page")


async def probe_radare2(session: ClientSession) -> None:
    await require_tools(session, "radare2", {"open_file", "show_info", "close_file"})
    opened = await session.call_tool("open_file", {"file_path": str(SMOKE_BINARY)})
    if opened.isError or "successfully" not in result_text(opened).lower():
        raise RuntimeError(f"radare2 open_file failed: {result_text(opened)}")
    info = await session.call_tool("show_info", {})
    if info.isError or "format" not in result_text(info).lower():
        raise RuntimeError(f"radare2 show_info failed: {result_text(info)}")
    closed = await session.call_tool("close_file", {})
    if closed.isError:
        raise RuntimeError(f"radare2 close_file failed: {result_text(closed)}")


PROBES = {
    "angr": probe_angr,
    "playwright": probe_playwright,
    "radare2": probe_radare2,
}


async def probe_server(name: str, config: dict[str, Any]) -> None:
    parameters = server_parameters(name, config)
    with anyio.fail_after(90):
        with Path(os.devnull).open("w", encoding="utf-8") as errlog:
            async with stdio_client(parameters, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    await PROBES[name](session)
                    print(
                        f"PASS MCP runtime {name}: "
                        f"{initialized.serverInfo.name} {initialized.serverInfo.version}"
                    )


async def async_main() -> int:
    if not SMOKE_BINARY.is_file():
        print(f"FAIL MCP runtime smoke binary missing: {SMOKE_BINARY}")
        return 1
    try:
        servers = load_servers()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"FAIL MCP runtime config: {exc}")
        return 1

    failures = 0
    for name in REQUIRED_SERVERS:
        config = servers.get(name)
        if not isinstance(config, dict):
            print(f"FAIL MCP runtime {name}: server is not configured")
            failures += 1
            continue
        try:
            await probe_server(name, config)
        except Exception as exc:
            print(f"FAIL MCP runtime {name}: {type(exc).__name__}: {exc}")
            failures += 1
    print(f"MCP runtime summary failures={failures}")
    return 1 if failures else 0


def main() -> int:
    return anyio.run(async_main)


if __name__ == "__main__":
    raise SystemExit(main())
