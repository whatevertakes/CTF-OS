# Manual Claude Rescue Solver

Manual Claude Rescue is an exact-run external solver handoff for an active `LIVE_CONTEST` Codex Solve. It is not a second CTF-OS, a race child, or an automatic model router. Reusing the current run keeps challenge identity, authorized targets, typed receipts, sandbox policy, and the protected flag path authoritative in one place.

## Operator lifecycle

```text
Codex Solve
→ operator requests rescue preparation
→ CTF-OS validates the exact mutable run and creates one immutable packet/workspace/sandbox
→ operator pauses Codex and manually starts Claude in the printed directory
→ Claude uses ctf-tool and writes CLAUDE_RETURN.json
→ operator stops Claude and resumes Codex
→ Codex validates the return as candidate insight and runs 1–3 decisive experiments
→ existing milestone/working-PoC/verified remote receipt path
→ human submission
```

No Python component starts, supervises, restarts, or routes Claude or Codex. Preparation is live-only and rejects benchmark A/B/C/D, matched attempts, sealed/accepted/solved runs, verified remote receipts, submission recommendation, and terminal convergence.

## Exact-run architecture

Every rescue is bound to `run_id`, `attempt_id`, `challenge_instance_id`, challenge identity, input fingerprint and scheme, target revision, snapshot digest, transformation seed, solve mode, repository commit, operation ID, rescue ID, and packet digest. The directory is `runs/<run-id>/rescue/<rescue-id>/`; `--run-id` and `--rescue-id` are never inferred from `ACTIVE_RUN`.

`RESCUE_LEDGER.jsonl` is append-only and authoritative for rescue lifecycle. `RESCUE_STATE.json` is a rebuildable projection. Core `STATE.json`, candidates, milestones, flag receipts, race lineage, delegation plans, and branch widths are not rescue projections and are never changed by prepare or return validation.

Packet truth comes from exact-run sources in this order: run manifest, state/launch identity, typed milestones, committed working-PoC receipts, verified candidate/flag receipts, race lineage, candidate/control views, referenced worker results, and auxiliary race events. Generic narrative does not create confirmed truth. Operator `leading_path` and `current_blocker` are candidates.

## Profiles

| Profile | Requested main | Generated subagents | Intended use |
|---|---|---|---|
| `standard` | `sonnet` | none | Strong single Claude Code baseline and default |
| `assisted` | `sonnet` | bounded Haiku recon/evidence plus Sonnet builder/alternate | Explicit request for helpers |
| `deep` | `claude-fable-5` | clean-room/evidence Haiku plus alternate/builder Sonnet | Explicit deep/Fable request only |

Assisted permits at most two initial Haiku calls, one Sonnet builder, and three initial subagent calls total. Deep uses the same bounded integration principle. Main owns attack-family selection and remote judgment; nesting is not assumed.

`requested_lead_model` is intent. `observed_lead_model` is recorded only by `rescue-runtime-record` with a bounded evidence file containing the observation. Requested Fable is never copied into observed state. If Fable explicitly refuses or routing prevents progress, `START.md` shows `claude --model opus` only as a new human-started session; there is no automatic fallback.

## Tool, memory, and sandbox contracts

The generated wrapper fixes repository root, exact run, rescue ID, sandbox metadata, and packet digest. Claude uses only:

```bash
./ctf-tool status
./ctf-tool exec -- <direct argv>
./ctf-tool import-input <safe-relative-path>
./ctf-tool import-input --all-bounded
```

Commands execute in the exact external-rescue container. `/challenge` and `/context` are read-only. Only this rescue's `work/`, `evidence/`, and `artifacts/` are writable bind mounts. The repository, `.git`, home, Docker socket, SSH/browser/cloud/kube credentials, other runs, and other workers are not mounted. A managed service remains Sol-owned and attach-only.

`RESCUE_COMMANDS.jsonl` stores bounded typed receipts with direct argv, digests, output excerpt, preserved output evidence, network counters/target index, and artifact snapshots. Repeating an identical command family without changed output or artifacts produces an advisory. Deterministic `context/rescue-memory.json` replaces recurring free-form status summaries.

## Return and Codex validation

Allowed verdicts are `REMOTE_FLAG_OBTAINED`, `REMOTE_READY_HANDOFF`, `CONFIRMED_BREAKTHROUGH`, `NO_NEW_PATH`, and `ERROR`. Remote flag claims identify a command receipt and exploit artifact; host, port, protocol, argv, output, and network proof come from the receipt. Remote-ready handoff identifies one executable artifact, exact argv, target index, success/kill conditions, and a 1–3 experiment bound.

`rescue-return-validate` verifies identity, packet digest, safe paths, hashes, command receipts, exact declared target observation, preserved output, and the current flag pattern. It writes `CODEX-RESUME.md` only. It does not create a candidate, milestone, working-PoC receipt, flag receipt, submission recommendation, or submission.

## Adopted and excluded patterns

| Source pattern | Adopted | Deliberately excluded |
|---|---|---|
| Claude Code single solver | One session directly handles evidence, tools, PoC, and remote | Chat-only handoff |
| D-CIPHER roles | Recon/evidence, strategy main, exploit builder in assisted/deep | Auto-prompter model and default swarm |
| EnIGMA tools | Real isolated command execution, network, artifacts, receipts | v1 persistent GDB/TCP session manager |
| Veria | Isolated sandbox, first-to-flag objective, repetition warning, structured result | Always-on swarm, coordinator model, auto-submit |
| Anthropic CTF operations | Typed deterministic memory and replayable commands | Repeated long free-form summaries |

Future tool extensions may add `ctf-tool session open/send/read/close` for bounded persistent GDB or TCP interaction. They must preserve exact rescue ownership, direct logging, target scope, and manual model lifecycle.
