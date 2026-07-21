---
name: ctf-claude-rescue-prepare
description: Prepare an exact-run, operator-started Claude rescue workspace without launching Claude. Use for “Claude 구조대 준비해라”, “클로드 구조대 준비해라”, “Claude에게 넘길 준비해라”, “구조대 폴더 만들어라”, “Haiku를 포함한 Claude 구조대 준비해라”, “deep Claude 구조대 준비해라”, or “Fable 구조대 준비해라”.
---

# Manual Claude Rescue Preparation

Prepare one immutable rescue packet for the current exact LIVE solve run. The current Sol session remains the owner of the solve. Never launch, supervise, or restart Claude, Codex, or another model process.

## Workflow

1. Read `AGENTS.md`, `ctf_os/resources/agent-policy.md`, and `.codex/skills/ctf-solve/SKILL.md`. Preserve the exact-run, protected flag-receipt, and human-submission contracts.
2. Identify the current exact `run_id`. Do not let `ACTIVE_RUN.json` select a run implicitly. Confirm that the run is LIVE, mutable, unsealed, and has no terminal or verified-remote-flag receipt.
3. State the current leading exploit path in one sentence and the current blocker in one sentence.
4. Read recent typed milestone receipts and their referenced evidence. Treat narrative events only as supplemental context.
5. If the last decisive experiment was actually performed but not recorded, record only that real experiment through the existing milestone command. Never invent an experiment, evidence, or narrative milestone.
6. Choose one mode: `BLOCKER_BREAK`, `PRIMITIVE_TO_POC`, `REMOTE_ENDGAME`, `FRESH_REINTERPRETATION`, or `FLAG_VERIFICATION`.
7. Use `standard` unless the operator explicitly requested helpers or deep/Fable. An explicit Haiku-assisted request uses `assisted`; an explicit deep/Fable request uses `deep`. Do not infer either from elapsed time or difficulty.
8. Run `rescue-prepare` with the selector, contest, exact `--run-id`, mode, profile, one exact objective, one exact blocker, the one-sentence leading path, and a stable `--operation-id`.
9. If preparation says the Sol-owned managed service is not running, start that service from the current Sol session through the existing service path, then rerun the same preparation. Rescue preparation never takes service ownership.
10. Do not run the printed `claude` command. The human chooses whether and when to start Claude in a separate terminal.

## Required handoff

End with these fields and no claim that Claude has started:

```text
Claude Rescue Prepared
Run:
Rescue ID:
Mode:
Profile:
Requested model:
Path:
Start command:
Fallback command if manually needed:
Codex resume instruction:
```

The fallback is a manually approved command only. Never treat requested Fable as observed Fable or automatically restart it as Opus.
