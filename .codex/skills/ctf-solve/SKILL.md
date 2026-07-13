---
name: ctf-solve
description: Deep-solve exactly one authorized CTF challenge with the current Sol session as lead and an adaptive native-agent swarm/race. Use for requests such as "1번 문제 풀어라", "pwn/NBB 풀어라", "NBB deep solve", or "이 문제 swarm으로 풀어라" after intake has been completed.
---

# CTF solve swarm

The current user-opened Sol session is the sole lead orchestrator. Never run Codex from Python or a shell. Never submit a flag.

## Load and select

1. Read root `AGENTS.md`, `contest.md`, `ctf_os/resources/agent-policy.md`, the matching `ctf_os/resources/knowledge/playbooks/<category>.md`, and prior challenge output.
2. Run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<name>'`.
3. Stop on a stale/missing intake index, BLOCKED context, or ambiguous selector. Show candidates instead of choosing one.
4. Read every path returned in `read_paths`, plus `STATE.json`, `FINDINGS.md`, `evidence.log`, and relevant prior worker artifacts.

## Adaptive race

Start with about three non-overlapping native branches unless the challenge is obviously trivial. Use available native delegation directly. If exact model selection exists, prefer Luna for broad/cheap recon, Terra for harnesses and implementation, and Sol for hard reasoning/takeover; otherwise assign those roles without claiming model pinning.

- Phase 1 recon: define distinct hypotheses and explicit file/remote scope. Typical branches are static attack-surface analysis, local reproduction/harness, and an independent alternate attack family.
- Phase 2 selection: compare evidence, failed hypotheses, experiment cost, expected success, duplication, and remote risk. Continue two exploit branches when confidence is low.
- Phase 3 exploit race: assign genuinely different primitives or implementation paths. Do not duplicate the same solver. Record failures too.
- Phase 4 cross-pollination: append supported/rejected/inconclusive results with `record-finding`; send useful discoveries to active branches, terminate low-value work, and let the lead Sol take over stalled high-value analysis.
- Phase 5 verification: rerun from clean conditions. Use an independent branch or lead verification to distinguish the real challenge flag from examples/placeholders.

Each worker owns only `output/<contest>/<category>/<challenge>/workers/<branch-id>/` and the corresponding sandbox. Workers return concise evidence, commands, outputs, hypotheses tested, files produced, and next step. They must not access another challenge, undeclared network target, host credentials, or user files.

## Sandbox and evidence

Create an attempt with `sandbox-create '<selector>' --contest '<name>' --branch '<id>'`. Execute direct argv with `sandbox-exec '<.../sandbox.json>' --timeout N -- <command>`. Input is `/challenge` read-only; only `/work` and `/artifacts` are writable. Export final solver files through `/artifacts`, then always call `sandbox-cleanup`.

Record material claims with `record-finding '<selector>' --branch '<id>' --status supported|rejected|inconclusive --summary '...' --evidence '...'`. Keep the final solver under `exploit/` and ensure `reproduce.sh` starts from documented conditions.

Call `verify-result` only with observed evidence. Pass `--local-evidence` and `--independent-evidence` as unique substrings identifying two different successful `sandbox_exec` receipts whose stdout contains the candidate; remote challenges also require `--remote-evidence` for a third receipt. Local reproduction, independent rerun, pattern match, exploit presence, current input fingerprint, and remote reproduction when applicable are all required for `READY_FOR_HUMAN_SUBMISSION`. A flag-looking string or boolean assertion alone remains `VERIFICATION_REQUIRED`.

Return: problem, state, exact verified flag candidate if ready, local/remote/independent/pattern checks, reproduce path, core vulnerability, and the warning that submission is manual. Never claim SOLVED when verification is incomplete.
