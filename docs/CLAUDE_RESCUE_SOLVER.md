# Manual Claude Rescue Solver V3

Manual Claude Rescue is an exact-run, operator-started external solver handoff for an active `LIVE_CONTEST` Codex Solve. It is not a second CTF-OS, a race child, a scheduler, an automatic model router, or a flag submitter.

## Operator lifecycle

```text
Codex Solve
→ operator identifies a bottleneck
→ CTF-OS creates one immutable packet, workspace, and category sandbox
→ operator pauses Codex and starts Claude in a new terminal
→ Claude uses the fixed-identity MCP/ctf-tool and persistent sessions
→ Claude returns a remote flag or remote-ready exploit
→ operator stops Claude and resumes Codex
→ Codex validates canonical receipts and promotes an exact-run flag receipt
→ human submits the flag
```

No Python component starts, supervises, restarts, or routes Claude or Codex. Preparation rejects frozen benchmark A/B/C/D attempts, sealed/accepted/solved runs, verified remote receipts, submission recommendation, and terminal convergence. Rescue preparation and return validation do not mutate race lineage, milestones, candidates, or protected flag state.

## Exact identity and packet compatibility

Every rescue is fixed to `run_id`, `attempt_id`, `challenge_instance_id`, challenge identity, input fingerprint and scheme, target revision, snapshot digest, transformation seed, solve mode, repository commit, operation ID, rescue ID, sandbox image identity, and packet digest. The source run keeps only its ledger and immutable pointer; the Claude workspace directory is `CTF-OS-claude/runs/<contest>/<category>/<challenge>/<run-id>/<rescue-id>/`. Tools never infer another run from `ACTIVE_RUN`.

New packets use schema version 2. Schema version 1 remains readable and validatable. `RESCUE_PACKET.json` is immutable; all live state is append-only and reconstructable:

- `RESCUE_LEDGER.jsonl`: lifecycle and close/recovery events
- `RESCUE_COMMANDS.jsonl`: one-shot command receipts
- `RESCUE_SESSIONS.jsonl`: persistent session receipts
- `CLAUDE_SESSION_EVENTS.jsonl`: Claude Code lifecycle hooks
- `RESCUE_PROGRESS.jsonl` and `RESCUE_LIVE_STATE.json`: typed live memory and projection
- `RESCUE_TASKS.jsonl`: typed subagent task/results
- `KNOWLEDGE_SOURCES.jsonl` and `KNOWLEDGE_HINTS.jsonl`: bounded research evidence
- `RESCUE_TELEMETRY.jsonl`: event timing and observed counts

## Profiles

| Profile | Requested main | Generated subagents | Purpose |
|---|---|---|---|
| `standard` | Sonnet | none | strong single-Claude baseline |
| `assisted` | Sonnet | Haiku recon/evidence, Sonnet builder/alternate | bounded parallel assistance |
| `deep` | Opus | Haiku evidence/recon, Sonnet builder/alternate | complex exploit chains and plateaus |
| `fable-strategy` | `claude-fable-5` | clean-room Haiku, Sonnet alternate/builder | independent reframing and attack-family selection |

Assisted initially permits at most two Haiku calls, one Sonnet implementation call, and three subagent tasks total; active hypotheses are capped at two. Subagent nesting is forbidden. Mythos or another restricted model is never hard-coded and is available only through an explicit `--lead-model <full-model-id>` override.

Requested and observed model identity are different. `START.md` records the requested model, expected cyber routing/fallback behavior, retention/account requirement, and `observed model: pending runtime hook`. Only a `SessionStart` hook can make runtime model evidence authoritative; `rescue-runtime-record` remains a compatibility fallback when no hook evidence exists.

The implementation was developed on 2026-07-21 on a host without a locally installed `claude` executable, so local installed-version feature probing reports `UNAVAILABLE`. The generated runtime contract follows the official Claude Code CLI, hook, subagent, MCP, and settings documentation. An operator must run `claude --version` and `claude --help` on the execution host and review `START.md` before starting a model.

Official compatibility references rechecked on that date:

- [Claude Code CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-usage)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Claude Code project settings](https://code.claude.com/docs/en/claude-directory)
- [Claude model overview](https://platform.claude.com/docs/en/about-claude/models/overview)
- [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
- [Refusals and fallback behavior](https://platform.claude.com/docs/en/build-with-claude/refusals-and-fallback)

## Claude lifecycle and resume

Project settings register `SessionStart`, `PreCompact`, `PostCompact`, `SessionEnd`, `SubagentStart`, `SubagentStop`, `TaskCreated`, and `TaskCompleted`. Unsupported hooks are listed in `START.md` from installed-CLI probing instead of being silently assumed.

`SessionStart` records session ID, actual model, source (`startup`, `resume`, `compact`, or `clear`), transcript path, cwd, agent type, and start time. Its stdout injects only bounded exact identity, blocker, active hypotheses, last decisive experiment, active persistent sessions, latest working artifact, and next action. `PreCompact` records whether a checkpoint exists and asks for a short checkpoint only when missing; `PostCompact` records a bounded excerpt/digest without promoting it to CTF truth. `SessionEnd` records duration, latest progress receipt, and open sessions.

When a session ID exists, `rescue-show` prints:

```bash
claude --resume '<exact-session-id>'
claude --continue
```

Explicit ID resume is preferred. Neither command is executed by CTF-OS.

## Tools, permissions, and sandbox

The generated `.mcp.json` and `ctf-tool` wrapper fix repository root, run ID, rescue ID, packet digest, and sandbox metadata. The priority is typed project-local MCP, then `./ctf-tool`; narrative alone never creates an observation.

The container mounts `/challenge` and `/context` read-only. Only this rescue's `/work`, `/evidence`, `/artifacts`, and `/sessions` are writable. The repository, `.git`, home, Docker socket, SSH/browser/cloud/kube credentials, other runs, and other workers are not mounted. A managed service remains Sol-owned and attach-only.

Generated settings allow rescue-local read/write/edit, the fixed wrapper, the `ctf-rescue` MCP, declared profile agents, hooks, and policy-selected research tools. They use `dontAsk` when the probed CLI supports it, otherwise a fixed allowlist. `--dangerously-skip-permissions` is never emitted.

`TOOLCHAIN_RECEIPT.json` records selected tag, actual image ID/repo digest, OS, architecture, CPU/GPU observations, tool paths/versions, Python/packages, endpoints, and persistent-session capabilities. Category contracts classify tools as `REQUIRED`, `RECOMMENDED`, `OPTIONAL`, or `UNAVAILABLE`; a missing required tool is an actionable preparation/runtime inventory failure.

Interactive session, MCP, knowledge, and live validation details are in:

- [CLAUDE_RESCUE_INTERACTIVE_TOOLS.md](CLAUDE_RESCUE_INTERACTIVE_TOOLS.md)
- [CLAUDE_RESCUE_KNOWLEDGE.md](CLAUDE_RESCUE_KNOWLEDGE.md)
- [CLAUDE_RESCUE_LIVE_TEST.md](CLAUDE_RESCUE_LIVE_TEST.md)

## Return, receipts, and flag promotion

Allowed verdicts remain `REMOTE_FLAG_OBTAINED`, `REMOTE_READY_HANDOFF`, `CONFIRMED_BREAKTHROUGH`, `NO_NEW_PATH`, and `ERROR`. A flag claim references either a canonical one-shot command receipt or a `SESSION_OUTPUT_OBSERVED` receipt. Output, target/protocol observation, sandbox image identity, artifact snapshot, and packet/run ownership come from that receipt, not caller-supplied booleans or copied output.

`REMOTE_READY_HANDOFF` requires the exploit path, SHA-256, exact next argv, valid target index, success/kill conditions, and one to three remaining experiments. The artifact must be the executable or the interpreter's first script argument; an unrelated executable file cannot satisfy validation.

`rescue-return-validate` writes `CODEX-RESUME.md` but does not create a candidate, milestone, working-PoC receipt, flag receipt, submission recommendation, or submission. After Codex validates the return, the only rescue promotion path is exact-run and receipt-derived:

```bash
uv run python -m ctf_os.agent_tools rescue-flag-promote '<selector>' \
  --contest '<contest>' --run-id '<exact-run-id>' --rescue-id '<rescue-id>' \
  --execution-receipt-id '<command-or-session-observation-id>' \
  --candidate 'CTF{...}' --exploit-artifact 'artifacts/solve.py'
```

The protected receipt adds `source_type=CLAUDE_RESCUE`, rescue attempt, packet digest, execution receipt, sandbox image ID, and output evidence digest. It never trusts caller-supplied host, port, protocol, output, network boolean, or arbitrary evidence path. Human submission remains the final oracle.

## Recovery and close

Rescue one-shot timeouts default to `retain_on_timeout=true`; ordinary worker policy is unchanged. `./ctf-tool sandbox status` inspects Docker rather than metadata alone and reports `RUNNING`, `STOPPED`, `MISSING`, `RECOVERABLE`, or `RECOVERY_REQUIRED`. Recovery requires exact identity, packet digest, input fingerprint, target revision, image identity, and managed-service state. Persistent sessions become `STALE` after recovery and are never silently recreated.

Close explicitly closes open sessions, removes only the rescue sandbox/resource request, and preserves the workspace. A rescue that failed before sandbox creation can close with `sandbox_cleanup=NOT_PRESENT`. `integrated` and `flag-obtained` require a milestone, working-PoC, protected flag, or validated command/session observation receipt; evidence-free confirmation is rejected.
