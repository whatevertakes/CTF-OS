---
name: ctf-claude-rescue-prepare
description: Prepare an exact-run, operator-started Claude rescue workspace without launching Claude. Use for “Claude 구조대 준비해라”, “Claude assisted 구조대 준비해라”, “Claude Opus 구조대 준비해라”, “Fable 전략 구조대 준비해라”, “외부 검색 허용하고 구조대 준비해라”, or equivalent manual rescue preparation requests.
---

# Manual Claude Rescue Preparation

Prepare one immutable rescue packet for the current exact LIVE solve run. This repository owns the generated workspace under its `runs/` tree; the source `CTF-OS-main` exact run remains the owner of Solve state. Never launch, supervise, or restart Claude, Codex, or another model process.

## Workflow

1. Read `AGENTS.md`, `ctf_os/resources/agent-policy.md`, and `.codex/skills/ctf-solve/SKILL.md`. Preserve the exact-run, protected flag-receipt, and human-submission contracts.
2. Identify the current exact `run_id`. Do not let `ACTIVE_RUN.json` select a run implicitly. Confirm that the run is LIVE, mutable, unsealed, and has no terminal or verified-remote-flag receipt.
3. State the current leading exploit path in one sentence and the current blocker in one sentence.
4. Read recent typed milestone receipts and their referenced evidence. Treat narrative events only as supplemental context.
5. If the last decisive experiment was actually performed but not recorded, record only that real experiment through the existing milestone command. Never invent an experiment, evidence, or narrative milestone.
6. Choose one mode: `BLOCKER_BREAK`, `PRIMITIVE_TO_POC`, `REMOTE_ENDGAME`, `FRESH_REINTERPRETATION`, or `FLAG_VERIFICATION`.
7. Select profiles literally: ordinary rescue is `standard`/Sonnet; assisted is `assisted`/Sonnet; explicit Opus/deep is `deep`/Opus; explicit Fable strategy is `fable-strategy`/`claude-fable-5`. Never merge Opus deep and Fable strategy. A restricted model such as Mythos is allowed only when the operator supplies the full `--lead-model` ID.
8. Select research policy from explicit operator/contest policy. “외부 검색 허용” means `public-web`; an explicit already-connected research MCP request means `public-web-and-mcp`. If policy cannot be established, use `offline` and state that in the handoff.
9. Run `rescue-prepare` with selector, contest, exact `--run-id`, mode, profile, research policy, one exact objective, one exact blocker, the leading path, and a stable `--operation-id`.
10. Check the returned `toolchain_receipt`; missing `REQUIRED` category tools are an actionable preparation failure. Report installed Claude CLI capability status exactly as recorded; never invent support when the CLI is absent.
11. If preparation says the Sol-owned managed service is not running, start that service from the current Sol session through the existing service path, then rerun the same preparation. Rescue preparation never takes service ownership.
12. Do not run the printed `claude`, resume, or continue command. The human chooses whether and when to start Claude in a separate terminal.

## Required handoff

End with these fields and no claim that Claude has started:

```text
Claude Rescue Prepared
Run:
Rescue ID:
Mode:
Profile:
Requested model:
Research policy:
Toolchain receipt:
Path:
Start command:
Resume command if a runtime session already exists:
Codex resume instruction:
```

Only a Claude Code `SessionStart` hook may establish the authoritative observed model. Never treat requested Fable as observed Fable or automatically restart it as Opus/Sonnet.
