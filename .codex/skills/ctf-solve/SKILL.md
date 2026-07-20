---
name: ctf-solve
description: Competition-first solve of exactly one authorized CTF challenge with the current user-opened Sol session as lead attacker and a native first-to-flag race. Use for "1번 문제 풀어라", category/name, challenge names, deep solve, or swarm requests.
---

# CTF solve — exploit first

`ctf_os/resources/agent-policy.md` is authoritative and governs every step below. This is a timed CTF solve, not a research task: obtain the first valid flag, prefer the shortest executable exploit path, and explain later. The current user-opened Sol session is lead attacker. Never run Codex or Claude from Python/a shell, call a model API, or submit a flag automatically.

## Start with bounded observation

1. The current user-opened session remains lead Sol from preparation through remote flag acquisition. Read root `AGENTS.md`, the authoritative agent policy, and only the selected category playbook.
2. Run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'` in this session.
3. Use the returned `solve_launch_context` as the authoritative launch context for this selected challenge. It contains the current identity, input fingerprint, declared scope, bounded priority files, environment, and optional selected-challenge Triage fields. Do not load the full contest Board or require the user to run another command.
4. Directly observe the priority files and actual runtime results. Triage and Intake attack surfaces are observation-ordering hints only. They are not confirmed vulnerabilities or exploit primitives. Discard a hint immediately when the first decisive experiment refutes it. A Triage recommendation, difficulty, or success estimate never substitutes for an exploit hypothesis based on actual evidence.
5. Spend no more than roughly 60–90 seconds and no more than the category playbook's fast-recon command budget. Stop at the first concrete primitive even if budget remains. Read raw logs/inventories only for a current exploit hypothesis.
6. Form at most three concrete active exploit hypotheses from direct file/runtime observation.
7. Run the cheapest decisive experiment for the leading hypothesis, then kill or promote it before adding another.
8. Move immediately to the smallest working PoC and the declared remote as soon as the path is plausible.

`prepare-challenge` syncs the manifest and repairs missing or stale Intake state inside the same call. Do not ask the user to run Intake/Triage commands, open a preparation session, open a new solve session, or provide the challenge and remote again. Stop only when the selector is genuinely ambiguous; challenge input is missing, damaged, or cannot be prepared safely; scope is missing or requires an out-of-scope action; a required target is undeclared; required host credentials were not provided; or metadata is damaged or unsafe.

At budget exhaustion, emit exactly this compact decision state:

```text
Leading exploit path:
Decisive next experiment:
Kill condition:
Expected time to PoC: immediate | few experiments | long computation
```

Each active hypothesis contains only `expected primitive`, `cheapest decisive experiment`, `success condition`, and `kill condition`; `reopen_condition` is optional.

## Start an evidence-driven race

Choose Tier 0–4 and run one atomic `race-plan-start`. Prefer an evidence-driven `--branch-spec`; omit it only when evidence is too thin, because category templates are fallback lanes rather than the attack plan.

```bash
uv run python -m ctf_os.agent_tools race-plan-start '<selector>' \
  --contest '<contest>' --tier 2 --tier-reason '<leading mechanisms and evidence>'
```

- Tier 0: Sol directly drives the minimal exploit; optionally one implementation/verifier child.
- Tier 1: two children plus Sol.
- Tier 2: three children plus Sol.
- Tier 3: four children plus Sol across distinct executable mechanisms.
- Tier 4: terminate low-proximity work and replace it while keeping useful concurrency full. Record why proximity stalled and choose a genuinely different exploit mechanism.

Immediately create capacity-admitted children using Codex runtime native delegation, mark each RUNNING, then create its sandbox. `race-plan-start`, `branch-admit`, Python, and sandbox commands never create a child. Requested model/reasoning are intent only; observed fields stay null without runtime evidence.

`independent-full-solve` means independently race for the shortest valid flag path. It does not mean comprehensive analysis: do not wait for siblings and preserve only evidence sufficient to exploit. Admission overlap remains advisory at 0.95; only a repeated session ID or materially exact duplicate is denied outside explicit race/verification exceptions.

## Execute the shortest loop

```text
observe → at most 3 exploit hypotheses → cheapest decisive experiment
→ kill or promote → smallest working PoC → local test when useful
→ declared remote as soon as plausible → immediate flag display
```

Sol concurrently owns core primitive reasoning, difficult exploit-chain decisions, minimal PoC synthesis, promising-artifact takeover, remote execution, and flag judgment. Do not wait as a router. Do not return to broad recon while a viable path is alive.

Workers publish `EXPLOIT_PRIMITIVE_CANDIDATE`, `EXPLOIT_PRIMITIVE_CONFIRMED`, `EXPLOIT_PRIMITIVE_REFUTED`, `WORKING_POC`, `FLAG_CANDIDATE`, or `REMOTE_FLAG_OBTAINED` before summaries. Candidate is not confirmed progress; confirmation requires a positive assertion and a category-appropriate negative/control receipt. Other checkpoints are useful only when they state the current hypothesis, decisive experiment, observed result, proximity change, next exploit action, and kill/continue decision. Facts, rejected hypotheses, decompilation, source notes, generic artifacts, and new files are not progress by themselves.

Utility is automatically evaluated after a blocker, primitive transition, working artifact, plateau, budget boundary, flag candidate, terminal result, scheduler update, or explicit control-loop tick—not after every command. `branch-utility` remains an explicit inspection tool. `PROGRESSING` requires real exploit-proximity gain; `BUMP_AND_RETRY` permits exactly one changed decisive experiment; `REPLACE_ATTACK_FAMILY` changes mechanism; `SOL_TAKEOVER` is the required handoff from a confirmed primitive to minimal PoC/endgame; `FLAG_PATH` goes to remote now. Apply sibling packets only when they directly resolve the current blocker. Scheduler scale-up is long-compute opt-in, and timeout retention follows the selected profile.

Sol performs management only after branch creation, an explicit blocker, exploit primitive, working artifact, plateau, flag candidate, or child termination. Preserve conflicts, but do not merge low-value reports or inspect every event.

## Sandboxes, long tools, and scope

Challenge input and `/context` are read-only; worker `/work`, `/evidence`, and `/artifacts` are private. A child may control only its exact branch-private service. Sol alone controls the shared service, global scheduler rebalance, and native child lifecycle. Category playbooks define the smallest allowed recon and exploit transition.

Quick probes and short PoCs run immediately. Do not repeat `resource-status`, `resource-request`, `resource-plan`, or rebalance before them. Use scheduler planning only before long symbolic execution, fuzzing, forensic scans, crypto/cracking, or AI inference; run those in bounded slices and continue only when exploit/solver proximity or necessary compute progress increases. New parallel harnesses use `CTF_OS_RECOMMENDED_WORKERS`.

Attack only the selected challenge and declared targets. Public/private/VPN/IPv6 and declared custom protocols are valid; cloud metadata, Docker gateways, undeclared LANs, unrelated hosts, other challenges, ambient credentials, and host SSH/browser/cloud/Docker data are forbidden. Preserve sandbox isolation and the branch mutation ledger.

## Flag fast path

When a branch obtains a candidate, publish it before any report. For a declared remote, preserve the exact command output, actual target observation, matching candidate, and existing exploit artifact, then call `flag-receipt-save`.

```text
REMOTE FLAG OBTAINED
Challenge: category/name
Flag: CTF{...}
Confidence: HIGH
Source: declared remote
Receipt: flag-receipts/remote-....json
Recommendation: submit immediately
Full clean replay: not required before human submission
```

`SUBMISSION_RECOMMENDED` is immediate. Stop low-value branches, retain at most one optional verifier, and let the human submit. Static rev/crypto and deterministic forensic paths may use the policy's artifact/provenance fast path. Strict replay is optional and may later produce `FULLY_VERIFIED`; never delay flag display for it.
