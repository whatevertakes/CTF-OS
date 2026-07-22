---
name: ctf-claude-handoff
description: Terminate the current exact CTF race and save its single manual evidence-backed HANDOFF.md.
---

# Manual Claude handoff

This request is a terminal command. Stop all new challenge, remote, service, and
worker activity. Do not prepare a new run or call Claude.

1. Confirm the exact active `run_id` from `race-status`.
2. Read only that run's `RUN.json`, `INPUT.json`, `RACE.json`,
   `BLACKBOARD.jsonl`, command/session receipts, and saved lane artifacts.
3. Write a bounded UTF-8 markdown file containing the exact run ID, challenge
   identity and scope, up to ten decisive executed experiments, observed output,
   confirmed/rejected result, the leading executable path, exact blocker,
   artifact paths/hashes, and one concrete next attack. Exclude internal
   reasoning, confidence-only claims, unexecuted commands, transcripts, other
   challenges, and unverified flags.
4. Terminate and save exactly one handoff:

   ```bash
   uv run python -m ctf_os.agent_tools race-handoff \
     --run-id '<run-id>' --markdown-file '<bounded-file>'
   ```

5. Immediately interrupt every returned native cancel target. Confirm stops,
   then run `race-cleanup --run-id '<run-id>'`.
6. Verify the returned `handoff_path` exists and end the Solve. Do not resume
   attacks, create another runtime, move original input, or submit a flag.
