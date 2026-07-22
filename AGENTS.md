# CTF-OS — Sol-native routing contract

`ctf_os/resources/agent-policy.md` is authoritative. `.codex/skills/ctf-solve/SKILL.md`
defines the one Solve procedure and the selected category playbook provides only
bounded tactics.

For a challenge name, category/name, “N번 문제 풀어라”, deep solve, or swarm
request, keep the current user-opened Sol session, prepare only that challenge,
and immediately run the first-to-flag swarm. Whole-contest Intake and Triage are
optional admin commands only when explicitly requested.
They are never Solve prerequisites.

Root is lead attacker, not coordinator-only. Successful preparation returns
three native spawn packets: independent, exploit-first, and tool-driven. Root
must call native `spawn_agent` for all three with `fork_turns=none` before any
additional recon, confirm only returned thread IDs as running, then continue its
own attack without waiting. Python never starts/stops models or submits flags.

Use only organizer-declared targets. Keep challenge input read-only and worker
work/evidence/artifacts private. Preserve challenge/attempt isolation, category
sandboxes, GPU/process resources, target scope, minimal executed commands and
artifacts, manual submission, and manual Claude handoff.
Never access the host Docker socket, SSH keys, browser profiles, personal cloud
credentials, cloud metadata, or undeclared private networks. Never submit a flag
automatically. Native delegation remains owned by Root.

The attack loop is minimal observation, one path, smallest executable attack,
real output, mutation or family replacement, remote, flag. Attack state and event
records are post-execution facts, not permissions. A sendable remote payload is
sent without replay or approval gates. The first valid target-observed flag is
shown immediately; Root cancels siblings and the human submits.

At 30 minutes replace up to two low-yield lanes after native stop. At 60 minutes
one bounded Sol max endgame lane is allowed only for an executed partial exploit
with a concrete reasoning blocker. At 90 minutes stop without automatic
extension and preserve a compact timeout handoff.

“클로드 구조대 준비해라” has priority over every new attack action. Load the
handoff skill, write the one evidence-backed `HANDOFF.md`, and end that Solve.
