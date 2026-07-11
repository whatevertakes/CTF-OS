# CTF-OS

CTF-OS is a local-first, multi-node agent for authorized CTF challenges. Every
member runs their own local node and Codex account. There is no central
executor, remote-worker control, shared Codex account, or CTFd auto-submit.
TeamSync is an append-only JSONL status/findings/flag ledger only.

## Quick start

```bash
uv run ctf-os init "SCA CTF 2026"
# Edit config.yaml to set team/member ownership and, for real workers,
# enable model_routing with config/model-routing.yaml.
# Add challenge metadata and files under incoming/SCA CTF 2026/.
uv run ctf-os doctor
uv run ctf-os parse
uv run ctf-os run --once --mock-worker --auto-confirm-flags
uv run ctf-os tui --team --readonly
uv run ctf-os sync merge
```

The generated configuration is deliberately mock-safe: model routing is off
until a real local Codex configuration is selected. `--mock-worker` does not
invoke Docker, Codex, or the network. Its output is labelled synthetic, uses a
`SYNTHETIC{...}` test value, and is stored only in a private synthetic local
namespace. It never publishes to TeamSync and must never be submitted.

For real runs, configure owned categories, a valid routing file, and the
per-attempt Docker image, then use:

```bash
uv run ctf-os run
uv run ctf-os sandbox exec ATTEMPT_ID -- "file /workspace/chall"
uv run ctf-os sandbox cleanup
```

## Operator commands

`ctf-os run` refreshes the dashboard while local attempts are active. In a TTY
it redraws one screen; redirected output stays a deterministic plain-text
render suitable for logs and tests. The dashboard distinguishes local/team
running work, duplicate claims, candidates versus solves, synthetic fixtures,
attempt model/profile/effort, strategy seed, findings/failures, and local
Codex/sandbox capacity warnings.

```bash
# Requeue exactly one FAILED challenge owned by this node.
uv run ctf-os retry web-login

# Pause/resume only a challenge owned by this local node.  Pause records a
# PAUSED TeamSync status; it never sends a command to another member.
uv run ctf-os pause web-login
uv run ctf-os resume web-login

# Poll local SQLite and TeamSync read-only until Ctrl-C; this never starts,
# stops, or controls a worker.
uv run ctf-os tui --readonly

# Follow merged TeamSync state and report recoverable incomplete/corrupt tails.
uv run ctf-os sync watch
```

`retry` refuses solved, foreign-contest, team-only, and non-failed challenges.
It records a durable `RETRY_QUEUED` event; a subsequent local `run` acquires a
new fenced attempt normally. `init <contest>` also refuses a mismatch with an
existing `config.yaml` contest name, even when `--force` is supplied.

`pause` is idempotent for an already paused local challenge. It cancels only
handles in this node's `LocalWorkerPool` and releases only containers bearing
the exact local team/member/contest/challenge/attempt labels. `resume` changes
only local `PAUSED` state back to `QUEUED`; the ordinary local watcher picks it
up later. Neither command is a remote command/control facility.

## KISIA four-member example

KISIA uses one shared TeamSync namespace while each person keeps their own
`config.yaml`, Codex login, SQLite state, Docker containers, and local worker
pool. Web ownership intentionally overlaps; the TUI reports duplicate running
claims rather than stealing or stopping another member's work.

```yaml
contest:
  name: "KISIA CTF 2026"
  team_id: "kisia-main"

# Put only this member's identity/categories in each local config.yaml.
member:
  name: "jiwoong"
  display_name: "Jiwoong"
  owned_categories: [pwn, web]

# Team ownership reference (copy the matching member section per machine):
# jiwoong:  [pwn, web]
# jueon:    [rev, cloud]
# hyunseok: [crypto, web]
# howon:    [forensics, misc]
sync:
  enabled: true
  type: file
  root: "sync"
  team_namespace: "kisia-main"
```

On each member's own PC:

```bash
uv run ctf-os doctor
uv run ctf-os parse
uv run ctf-os run
uv run ctf-os tui --team --readonly
```

The existing SCA setup remains separate: use its own `team_id` (for example
`sca-jiwoong-team` or `sca-hyunseok-team`) and never point an SCA node at the
`kisia-main` TeamSync namespace.

Challenge commands are sent as Docker argv and execute only inside the attempt
container. Each real attempt starts a parent-owned, attempt-local authenticated
filesystem spool broker with atomic publish and puts `./ctf-exec` in that
attempt's exact Codex workdir; the helper cannot access Docker and can send
only authenticated argv data to its own broker. The Codex child uses a strict,
user-config-free named permissions profile with host network access disabled.

Container egress is deny-by-default. `contest.md` may declare one exact
`http(s)://HOST[:PORT]/...` URL or `nc HOST PORT`; CTF-OS resolves it before
startup and the entrypoint allows only those resolved TCP IP/port pairs. If
Docker, its image, Codex, model routing, or a documented remote policy is
unavailable, a non-mock run stops with an actionable error; it never falls back
to host challenge command execution. `sandbox cleanup --all` remains
label-filtered to the configured team and local member.

Model routing roles:

- Sol: supervision, architecture, difficult strategy, final verification.
- Terra: normal implementation and exploit work.
- Luna: recon, summarization, and cheap parallel attempts.

The complete design is in [docs/CTF-OS_v1.3_LocalFirst_Requirements.md](docs/CTF-OS_v1.3_LocalFirst_Requirements.md).

## Local knowledge references

The local knowledge seed includes selected Markdown reference material from
[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills), pinned to
commit `0a3a9c41bdef1ffb845e71cb53a7a6adbec85956` and retained under its MIT
license. It is a local snapshot only: CTF-OS never executes its examples or
fetches its links. See [docs/knowledge.md](docs/knowledge.md) for the import
policy, attribution, audit command, and the explicit trust controls for
reviewed sections.
