---
name: ctf-solve
description: Competition-first solve of exactly one authorized CTF challenge with the current user-opened Sol session as lead attacker and a native first-to-flag race. Use for "1번 문제 풀어라", category/name, challenge names, deep solve, or swarm requests.
---

# CTF solve — exploit first

`ctf_os/resources/agent-policy.md` is authoritative and governs every step below. This is a timed CTF solve, not a research task: obtain the first valid flag, prefer the shortest executable exploit path, and explain later. The current user-opened Sol session is lead attacker. Never run Codex or Claude from Python/a shell, call a model API, or submit a flag automatically.

## Start with bounded observation

1. The current user-opened session remains lead Sol from preparation through human submission feedback and cleanup. You are the main attacker, not a coordinator-only process. Read root `AGENTS.md`, the authoritative agent policy, and only the selected category playbook.
2. Internally run `uv run python -m ctf_os.agent_tools prepare-challenge '<selector>' --contest '<contest>'` in this session. This compatibility command resumes the current attempt. Use `attempt-start` or `prepare-challenge --fresh-attempt` only when the user or benchmark contract requires an independent execution. This is not a separate user step.
3. Use the returned `solve_launch_context`, exact `attempt_id`, and `run_root` as authoritative for this selected challenge. The deterministic `challenge_instance_id` identifies the snapshot; the fresh `attempt_id` identifies the execution; `run_id` binds both. Never resolve a benchmark attempt through `ACTIVE_RUN`. Challenge-local intake/triage is only the minimum preparation needed to understand this problem; it is not a separate whole-contest phase. Do not load a whole-contest index or Board and do not require the user to run another command.
4. Directly observe the priority files and actual runtime results. Preflight observation hints only order inspection of this selected challenge. They are not confirmed vulnerabilities or exploit primitives. Discard a hint immediately when the first decisive experiment refutes it.
5. Spend no more than roughly 60–90 seconds and no more than the category playbook's fast-recon command budget. Stop at the first concrete primitive even if budget remains. Read raw logs/inventories only for a current exploit hypothesis.
6. Form at most three concrete active exploit hypotheses from direct file/runtime observation.
7. Run the cheapest decisive experiment for the leading hypothesis, then kill or promote it before adding another.
8. Move immediately to the smallest working PoC and the declared remote as soon as the path is plausible.

The current user-opened Sol session remains lead attacker from challenge-local preflight through remote flag acquisition. `prepare-challenge` synchronizes problem metadata and repairs only the selected challenge's missing, stale, or tampered local preparation state. Whole-contest Intake and Triage are not prerequisites and are never consulted by Solve. Do not ask the user to open a preparation or replacement Solve session, repeat problem information, or provide the remote again. If no remote was supplied, continue through the local or deterministic flag path. Missing optional information is not a blocker when safe execution can continue. Stop only when the selector is genuinely ambiguous; selected challenge input is missing, damaged, or cannot be prepared safely; scope required for the next action is missing; a required target is undeclared; required host credentials were not provided; or selected metadata is damaged or unsafe.

At budget exhaustion, emit exactly this compact decision state:

```text
Leading exploit path:
Decisive next experiment:
Kill condition:
Expected time to PoC: immediate | few experiments | long computation
```

Each active hypothesis contains only `expected primitive`, `cheapest decisive experiment`, `success condition`, and `kill condition`; `reopen_condition` is optional.

## Apply the explicit solve mode

Live competition defaults to `adaptive-race`, but that does not start children. Sol starts attacking immediately with active child width zero, performs the bounded 60–90 second observation above, then chooses 0–3 distinct evidence-backed mechanisms subject to capacity. Prefer an evidence-driven `--branch-spec`; omit it only when evidence is too thin, because category templates are fallback lanes rather than the adaptive attack plan.

```bash
uv run python -m ctf_os.agent_tools race-plan-start '<selector>' \
  --contest '<contest>' --mode adaptive-race \
  --branch-spec '<0-3 distinct evidence-bound mechanisms JSON>' \
  --tier-reason '<leading mechanisms and evidence>'
```

- `sol-only`: Sol alone; do not call `race-plan-start`, request a child, or create branch intent.
- `fixed-race`: exactly three frozen category-template child intents plus Sol, maximum model concurrency four, no width change, no replacement. If any child never reaches actual `RUNNING`, record environment failure/invalid treatment rather than silently continuing as a valid Sol-only result.
- `adaptive-race`: Sol plus 0–3 distinct evidence-selected mechanisms, active width initially zero, and at most one replacement after an exact plateau/refutation receipt. A child start failure is recorded; live solving continues on the Sol lane.
- Legacy tier is only compatibility/resource-envelope metadata: tier 0 maps to `sol-only`, tier 1–4 to `adaptive-race`. It never determines native children, running width, benchmark arm, model, or reasoning. Reject conflicting `--mode`/`--tier`.

Older documentation used the phrase `Tier 2: three children`; it is retained here only as a migration warning and is not runtime behavior. Explicit mode and lineage receipts are authoritative.

`race-plan-start` appends only `PLANNED` lineage events. Every initial or replacement branch uses `PLANNED → CAPACITY_ADMITTED → SANDBOX_READY → AWAITING_NATIVE_START → NATIVE_STARTED → RUNNING`. Only lineage branches whose latest lifecycle is `RUNNING` count toward active width. `race-plan-start`, `branch-admit`, Python, and sandbox commands never create a child; the current Sol session owns native delegation. Sol immediately continues its own attack while children start or fail; never wait for child startup. Requested model/reasoning are intent only; observed fields stay null without runtime evidence.

`RACE_LINEAGE.jsonl` is authoritative. Never mark a live branch stale, superseded, or replaced without exact native stop/child terminal, sandbox cleanup, and resource release receipts. A replacement is planned through the same lifecycle and cannot be admitted while the superseded live branch would exceed capacity. A whole-plan restart must close every prior started branch before publishing the next generation. `DELEGATION_PLAN.json` and `STATE.branches` are recoverable projections; Python manages those receipts but Sol alone starts and stops native sessions.

`independent-full-solve` means independently race for the shortest valid flag path. It does not mean comprehensive analysis: do not wait for siblings and preserve only evidence sufficient to exploit. Admission overlap remains advisory at 0.95; only a repeated session ID or materially exact duplicate is denied outside explicit race/verification exceptions.

## Execute the shortest loop

```text
observe → at most 3 exploit hypotheses → cheapest decisive experiment
→ kill or promote → smallest working PoC → local test when useful
→ declared remote as soon as plausible → immediate flag display
```

Sol concurrently owns core primitive reasoning, difficult exploit-chain decisions, minimal PoC synthesis, promising-artifact takeover, remote execution, and flag judgment. Do not wait as a router. Do not return to broad recon while a viable path is alive.

Sol and children use the same compact milestone receipt schema: `DECISIVE_EXPERIMENT`, `PRIMITIVE_CANDIDATE`, `PRIMITIVE_CONFIRMED`, `PRIMITIVE_REFUTED`, `WORKING_POC`, `REMOTE_ATTEMPT`, `FLAG_CANDIDATE`, `TYPED_BLOCKER`, `LONG_COMPUTE`, or `CHILD_TERMINAL_RESULT`. Candidate is not confirmed progress; confirmation requires a positive assertion and a category-appropriate negative/control receipt. Facts, decompilation, source notes, generic artifacts, and new files are not progress by themselves. Never publish `REMOTE_FLAG_OBTAINED` as a general event; only `flag-receipt-save` may create its receipt-bound event and submission recommendation.

`sandbox-exec` records its compact command receipt and progress-gate count automatically. For a direct command outside that path, immediately record its exact argv with `progress-command`; do not store full stdout. At a real milestone use `milestone-save`, for example `milestone-save '<selector>' --contest '<contest>' --type DECISIVE_EXPERIMENT --summary '<observed result>' --operation-id '<stable-experiment-id>' --details-json '{"decision":"KILL"}' -- python3 probe.py`. Use `--session-id sol-main` for the parent when runtime identity is not already supplied. A retry reuses the authoritative receipt and repairs only pending/failed projections; use a different operation ID only for an intentionally distinct repetition.

Utility is evaluated after typed high-value milestones and plateaus. Command-only drift creates one deduplicated control action. Decline/supersede/expire it with `control-action-ack`; mark it applied only through `control-action-apply` with the required exact run-local receipt. `PROGRESSING` requires real exploit-proximity gain; `REPLACE_ATTACK_FAMILY` changes mechanism; `SOL_TAKEOVER` converges a confirmed primitive on the minimal PoC/endgame; `FLAG_PATH` goes to remote now. With a validated local receipt and declared target, commit `WORKING_POC` and execute the one explicit remote attempt through `working-poc-commit`; otherwise record `REMOTE_ATTEMPT` or a typed target blocker before the deadline. `working-poc-commit` persists `EXECUTION_STARTED` before the executor. If that attempt has no durable result, never retry its operation ID: use `working-poc-resolve-unknown` to `RECORD_RESULT`, `ABANDON`, or authorize a distinct new operation ID. Apply sibling packets only when they directly resolve the current blocker.

Sol performs management only after branch creation, an explicit blocker, exploit primitive, working artifact, plateau, flag candidate, or child termination. Preserve conflicts, but do not merge low-value reports or inspect every event.

## Sandboxes, long tools, and scope

Challenge input and `/context` are read-only; worker `/work`, `/evidence`, and `/artifacts` are private. A child may control only its exact branch-private service. Sol alone controls the shared service, global scheduler rebalance, and native child lifecycle. Category playbooks define the smallest allowed recon and exploit transition.

Quick probes and short PoCs run immediately. Do not repeat `resource-status`, `resource-request`, `resource-plan`, or rebalance before them. Before symbolic execution, fuzzing, Sage, large extraction, or similar long work, record a `LONG_COMPUTE` contract with sandbox/container/process identity, exact argv, expected artifact and completion signal, maximum duration, checkpoint interval, resource requirement, cancel condition, and fallback plan. Heartbeat is valid only when Python observes the same process argv and an actual branch-local artifact change; caller booleans are not evidence. `LONG_COMPUTE_REVIEW` apply also requires decision-specific authoritative evidence: process termination with no remainder for cancellation, stopped process plus real marker/final artifact for completion, a fresh durable checkpoint receipt for continuation, or an exact fallback command receipt with the original process stopped. This is bounded, not an indefinite plateau exemption. New parallel harnesses use `CTF_OS_RECOMMENDED_WORKERS`.

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

`SUBMISSION_RECOMMENDED` is immediate and receipt-bound. Stop low-value branches, retain at most one optional verifier, and let the human submit. A static candidate remains LOW/MEDIUM unless an original validator, two exact independent extraction paths, remote acceptance, or explicit exact-byte proof validates it; static format matching alone never recommends submission. Strict replay is optional and never delays flag display.

After the human reports the outcome, bind it to the exact run and candidate:

```bash
uv run python -m ctf_os.agent_tools submission-result '<selector>' \
  --contest '<contest>' --run-id '<run-id>' --candidate-id '<candidate-id>' \
  --result accepted   # or: wrong
```

`WRONG` refutes only that candidate and returns the run to solving. `ACCEPTED` seals the solved evidence, creates branch stop packets, and starts sandbox/resource convergence. Sol owns native stop; record native stop receipts, rerun idempotent cleanup, and do not call the run `SEALED_CLEAN` while any native session remains `TERMINATION_PENDING`.
