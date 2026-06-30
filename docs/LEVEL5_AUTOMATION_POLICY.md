# Level 5 Automation Policy

Level 5 is bounded automation for existing Level 2 workflows. It automates
preflight, local benchmark wrapping, replay/proof orchestration, sanitized
reporting, cleanup of temporary artifacts, and repeatable runbooks.

It does not add solve capability, agents, Discord, GitHub remote automation, or
tool installation.

## Implemented Runtime

| Tool | Purpose |
|---|---|
| `tools/benchmark_runner.py` | Wrap `intake_challenge.py`, `replay_runner.py`, and `proof_validate.py` for a local dummy fixture or an existing challenge. |
| `tools/report_sanitize.py` | Produce redacted summaries from text reports or logs without modifying raw evidence. |
| `tools/cleanup_artifacts.py` | Remove explicitly targeted temporary/self-test/cache artifacts while refusing real challenge paths. |
| `tools/preflight_check.py` | Verify Level 0-5 framework files, local tools, Python modules, and config invariants. |

## Hard Boundaries

- Automation must never mark a challenge solved directly. Only
  `tools/proof_validate.py` can validate a solved claim.
- Automation must not commit flags, replay logs with flags, secrets, binaries,
  dumps, or `_selftest` artifacts.
- Automation must not use `challenges/_selftest` for real benchmark inputs.
- Automation must not place challenge-specific exploits under root `tools/`.
- Automation must preserve raw evidence locally and produce redacted summaries.
- Automation must fail closed when state or paths are ambiguous.
- Automation must print exact commands it runs.

## Benchmark Runner Contract

`tools/benchmark_runner.py` supports:

```bash
python3 tools/benchmark_runner.py dummy
python3 tools/benchmark_runner.py run <challenge-dir>
```

The runner:

1. Prints every subprocess command before running it.
2. Runs `tools/preflight_check.py`.
3. Runs `tools/replay_runner.py <challenge-dir>`.
4. Runs `tools/proof_validate.py <challenge-dir>`.
5. Writes `work/BENCHMARK_RUNNER_REPORT.md` with command return codes and
   sanitized output tails.
6. Leaves `state.json.status` untouched.

The dummy benchmark uses `challenges/_level5benchmark/misc/dummy-local`, not
`challenges/_selftest`.

## Sanitized Reporting Contract

`tools/report_sanitize.py <input> --output <output>` writes a redacted text
copy. It replaces flag-like strings, common secret assignments, bearer tokens,
and private-key blocks with placeholders. It does not delete or overwrite raw
evidence unless `--force` is explicitly supplied for an existing output path.

## Cleanup Contract

`tools/cleanup_artifacts.py` is dry-run by default and requires `--yes` to
delete. It refuses to remove paths outside the workspace, tracked git files,
root framework directories, or real challenge paths. Challenge temporary paths
must carry a cleanup marker such as `.selftest-artifact`, `.level5_selftest`, or
`.level5_benchmark`. It only removes:

- explicitly targeted, marker-bearing `challenges/_selftest/...` fixtures
- marker-bearing temporary `_level2selftest`, `_level3blind`, `_level4selftest`,
  and `_level5...` challenge fixtures
- `.cache/...`
- `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, and `__pycache__` directories
- `*:Zone.Identifier`

Use explicit targets for cleanup:

```bash
python3 tools/cleanup_artifacts.py --yes challenges/_selftest/<marked-fixture>
```

## Focused Secret Scan

Before committing Level 5 automation changes, run a focused scan over tracked
workspace source and policy files only. Do not scan cache or vendor trees by
default:

```bash
git grep -n -I -E '(api[_-]?key|token|secret|password|Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{16,}|BEGIN (RSA |OPENSSH |EC |DSA |PRIVATE )?PRIVATE KEY)' -- . \
  ':!*.pdf' \
  ':!.git' \
  ':!.cache' \
  ':!.venv' \
  ':!venv' \
  ':!node_modules' \
  ':!ghidra-mcp-cache' \
  ':!pyghidra_mcp_projects' \
  ':!.codex/tmp' \
  ':!.codex/state' \
  ':!vendor' \
  ':!third_party' \
  ':!build' \
  ':!dist' \
  ':!__pycache__' \
  ':!.pytest_cache' \
  ':!.mypy_cache' \
  ':!.ruff_cache'
```

## Repeatable Runbook

For a local automation check:

```bash
python3 tools/preflight_check.py
python3 tools/benchmark_runner.py dummy
python3 tools/report_sanitize.py <raw-report> --output <redacted-report>
python3 tools/cleanup_artifacts.py --yes challenges/_level5benchmark/misc/dummy-local
```

For an existing challenge:

```bash
python3 tools/benchmark_runner.py run challenges/<event>/<category>/<challenge>
python3 tools/proof_validate.py challenges/<event>/<category>/<challenge>
```

If any command fails, stop and inspect the generated report. Do not continue
into broader benchmark runs.

## Reference Alignment

Level 5 is intentionally narrow but follows established agent-evaluation
guidance:

- ReAct: keep action and observation traces inspectable.
- Reflexion: preserve feedback as text artifacts rather than relying on chat
  memory.
- SWE-agent: expose stable command interfaces instead of hidden harness state.
- AI Agents That Matter: measure benchmark readiness and failure modes, not just
  success labels.
- OpenAI and Anthropic harness guidance: build explicit tools, logs, and
  evaluators around agent work.

Reference URLs:

- https://arxiv.org/abs/2210.03629
- https://arxiv.org/abs/2303.11366
- https://arxiv.org/abs/2405.15793
- https://arxiv.org/abs/2407.01502
- https://openai.com/index/harness-engineering/
- https://www.anthropic.com/research/building-effective-agents
- https://www.anthropic.com/engineering/writing-tools-for-agents
