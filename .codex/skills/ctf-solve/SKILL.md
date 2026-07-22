---
name: ctf-solve
description: Race exactly one authorized CTF challenge to the first target-observed valid flag.
---

# CTF Solve

Read root `AGENTS.md` and `ctf_os/resources/agent-policy.md`. The current Root
session is Sol xhigh and the lead attacker. Do not load a category playbook into
initial context.

If the user requests a Claude handoff, stop before any new attack and follow the
handoff skill immediately.

1. Prepare exactly one challenge:

   ```bash
   uv run python -m ctf_os.agent_tools race-prepare '<selector>' --contest '<contest>'
   ```

2. Require `attack_ready: true` and `root_sandbox.status: READY`. If unavailable,
   report the exact returned blocker and recovery command. Never inspect or run
   challenge tools on the host.

3. Immediately append the highest-probability actual attack argv to
   `next_root_action.exec_command_prefix`. Root attacks continuously and never
   pauses merely to prepare workers.

4. When useful, call `race-bootstrap` once with one to three lane specs. Each has
   exactly `model_profile`, `role`, `task`, `context_mode`, and a distinct
   `attack_family`. Prefer independent Sol xhigh trajectories; use Terra high for
   a verified build direction and Luna high only for bounded mechanical work.
   Pass each returned `spawn_agent_args` unchanged to native `spawn_agent`, then
   record its thread ID with `race-spawn-confirm`. Do not confirm a worker before
   its private sandbox is READY.

5. Execute every analyzer, debugger, compiler, script, payload, solver, and
   remote request with `sandbox-exec` or a bounded persistent session. Move a
   remote-ready primitive to the declared remote immediately.

6. Share only compact events accepted from an existing command/session receipt.
   Fresh lanes receive no Root history. Directed lanes receive only the verified
   delta produced by the race engine.

7. Poll `race-status` while Root keeps attacking. Interrupt stagnant, duplicate,
   or remote-avoiding native lanes, then call `race-stop-confirm` with the exact
   native session ID. That confirmation cleans the stopped lane sandbox while
   preserving its host-side artifacts. Only then bootstrap a new attack family
   into a fresh private sandbox.

   Sol max is available only through `race-endgame` after minute 60, replacing
   one confirmed-stopped child when the blackboard already contains an
   executable partial artifact, two actual attack outputs, and an exact
   non-environment reasoning blocker. Its lease is ten minutes or two attacks.

8. When any execution returns a winner, display `display` immediately. Interrupt
   every returned sibling cancel target and stop analysis. Do not replay, build a
   report, or submit. A human submits the flag.

9. At 90 minutes, terminate without extension, interrupt native cancel targets,
   preserve needed lane-private artifacts, and run exact `race-cleanup`.

Maintain read-only input, declared-target-only egress, private writable paths,
Root-only service lifecycle, no host credentials/socket, and no automatic flag
submission throughout.
