# Claude Rescue V3 Live Test Gate

This gate validates runtime mechanics without running a Claude model or submitting a flag.

## Host preflight

```bash
git status --short
claude --version
claude --help
docker version
uv sync --frozen
```

If Claude Code is installed, compare `START.md` capability output with the installed help before a human model run. On the implementation host used on 2026-07-21, `claude` was not installed, so model/session lifecycle was tested only with hook fixture JSON. Do not convert that absence into an observed model value.

## Software gates

```bash
uv run pytest -q
python -m compileall -q ctf_os tests eval
git diff --check
uv build
```

The wheel must contain all rescue Markdown/JSON/YAML resources, including every category toolchain contract.

## Docker gate

Build the common/category image and run the explicit smoke gate:

```bash
sandbox/build-images.sh pwn
CTF_OS_DOCKER_SMOKE=1 uv run pytest -q tests/test_claude_rescue.py -k real_docker
```

The smoke gate covers category sandbox creation and inventory, stateful shell/GDB/REPL, text and binary TCP input, UDP protocol observation, timeout retention, container recovery with stale sessions, bind persistence, and exact fake-service flag promotion. It requires a real Docker daemon and is not replaced by a mocked unit test. CI runs it in a separate `docker-rescue-smoke` job; a runner without usable Docker must fail with an actionable daemon/image diagnostic.

## MCP and hook gate

The MCP tests launch the generated stdio server, send `initialize` and `tools/list`, then call inventory/session/progress/task/knowledge tools against fixed identity. Hook fixtures cover startup, resume, compact, session end, subagent start/stop, web-source capture, and offline blocking.

## Non-conclusions

These gates prove implementation and isolation behavior only. They do not prove higher remote flag rate, lower solve time, or model quality. No actual Claude, controlled replay, or automatic submission is part of this gate. Performance remains `INCONCLUSIVE` until the separate evaluation contract is executed.
